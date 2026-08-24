from __future__ import annotations

import abc
import ast
import dataclasses
import gc
import hashlib
import importlib
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import weakref
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from itertools import pairwise
from pathlib import Path
from types import CodeType, FunctionType, MappingProxyType, ModuleType
from typing import cast
from unittest.mock import patch

from router_dump_analyzer import plugin_identity
from router_dump_analyzer.plugin_identity import (
    PluginExecutableIdentityError,
    executable_callable_fingerprint,
    executable_module_target_fingerprint,
)


class PluginIdentityRuntimeImportTests(unittest.TestCase):
    @staticmethod
    def _clone_function(function: FunctionType) -> FunctionType:
        clone = FunctionType(
            function.__code__,
            function.__globals__,
            name=function.__name__,
            argdefs=function.__defaults__,
            closure=function.__closure__,
        )
        clone.__annotations__ = dict(function.__annotations__)
        clone.__dict__.update(function.__dict__)
        clone.__doc__ = function.__doc__
        clone.__kwdefaults__ = (
            None
            if function.__kwdefaults__ is None
            else dict(function.__kwdefaults__)
        )
        clone.__module__ = function.__module__
        clone.__qualname__ = function.__qualname__
        return clone

    @staticmethod
    def _clone_class(implementation: type[object]) -> type[object]:
        namespace = {
            name: value
            for name, value in vars(implementation).items()
            if name not in {"__dict__", "__weakref__"}
        }
        return type(implementation)(
            implementation.__name__,
            implementation.__bases__,
            namespace,
        )

    @contextmanager
    def _isolated_retained_token_registries(self):
        with plugin_identity._RETAINED_CAPABILITY_TOKEN_LOCK:
            weak_tokens = dict(
                plugin_identity._RETAINED_CAPABILITY_WEAK_TOKENS
            )
            strong_tokens = dict(
                plugin_identity._RETAINED_CAPABILITY_STRONG_TOKENS
            )
            plugin_identity._RETAINED_CAPABILITY_WEAK_TOKENS.clear()
            plugin_identity._RETAINED_CAPABILITY_STRONG_TOKENS.clear()
        try:
            yield
        finally:
            with plugin_identity._RETAINED_CAPABILITY_TOKEN_LOCK:
                plugin_identity._RETAINED_CAPABILITY_WEAK_TOKENS.clear()
                plugin_identity._RETAINED_CAPABILITY_WEAK_TOKENS.update(
                    weak_tokens
                )
                plugin_identity._RETAINED_CAPABILITY_STRONG_TOKENS.clear()
                plugin_identity._RETAINED_CAPABILITY_STRONG_TOKENS.update(
                    strong_tokens
                )

    def _retained_token_identity(self, value: object) -> str:
        digest = hashlib.sha256()
        plugin_identity._update_retained_capability_token(digest, value)
        return digest.hexdigest()

    def _dataclass_contract_identity(self, implementation: type[object]) -> str:
        digest = hashlib.sha256()
        plugin_identity._update_dataclass_class_contract(
            digest,
            implementation,
            budget=plugin_identity._TargetIdentityBudget(
                allow_unbound_source_objects=True
            ),
            scope_cache={},
            callable_cache={},
            active_callables=set(),
            identity_root=__name__,
            depth=0,
        )
        return digest.hexdigest()

    def _import_modules(
        self,
        sources: dict[str, str],
        *module_names: str,
    ) -> tuple[tempfile.TemporaryDirectory[str], tuple[object, ...]]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        for name, source in sources.items():
            (root / f"{name}.py").write_text(source, encoding="utf-8")
        sys.path.insert(0, str(root))
        importlib.invalidate_caches()
        try:
            modules = tuple(importlib.import_module(name) for name in module_names)
        except BaseException:
            sys.path.remove(str(root))
            for name in sources:
                sys.modules.pop(name, None)
            temporary.cleanup()
            raise
        return temporary, modules

    def _cleanup_modules(
        self,
        temporary: tempfile.TemporaryDirectory[str],
        *module_names: str,
    ) -> None:
        sys.path.remove(temporary.name)
        for name in module_names:
            sys.modules.pop(name, None)
        importlib.invalidate_caches()
        temporary.cleanup()

    def test_local_import_binds_changed_external_helper_behavior(self) -> None:
        helper_name = "_rda_identity_local_helper"
        factory_name = "_rda_identity_local_factory"
        temporary, (helper, factory_module) = self._import_modules(
            {
                helper_name: (
                    "def primary(value):\n"
                    "    return ('primary', value)\n\n"
                    "def alternate(value):\n"
                    "    return ('alternate', value)\n\n"
                    "route = primary\n"
                ),
                factory_name: (
                    "def factory(request, configuration):\n"
                    f"    import {helper_name} as helper\n"
                    "    return helper.route(request), configuration\n"
                ),
            },
            helper_name,
            factory_name,
        )
        try:
            first = executable_module_target_fingerprint(
                factory_name,
                "factory",
                factory_module.factory,
            )
            helper.route = helper.alternate
            second = executable_module_target_fingerprint(
                factory_name,
                "factory",
                factory_module.factory,
            )
        finally:
            self._cleanup_modules(temporary, helper_name, factory_name)
        self.assertNotEqual(first, second)

    def test_stateless_singleton_ordinary_method_rejects_forged_globals(
        self,
    ) -> None:
        module_name = "_rda_identity_stateless_singleton_method"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "def route(value):\n"
                    "    return ('declared', value)\n\n"
                    "class Capability:\n"
                    "    def apply(self, value):\n"
                    "        return route(value)\n\n"
                    "capability = Capability()\n"
                )
            },
            module_name,
        )
        try:
            budget = plugin_identity._TargetIdentityBudget()
            source_path = plugin_identity._module_file_source_path(
                module,
                budget=budget,
            )
            assert source_path is not None
            plugin_identity._source_singleton_class_shape_identity(
                module.Capability,
                module=module,
                module_name=module_name,
                qualified_name="Capability",
                source_path=source_path,
                budget=budget,
                scope_cache={},
                depth=0,
            )

            original = vars(module.Capability)["apply"]
            forged_globals = dict(original.__globals__)
            forged_globals["route"] = lambda value: ("forged", value)
            forged = FunctionType(
                original.__code__,
                forged_globals,
                name=original.__name__,
                argdefs=original.__defaults__,
                closure=original.__closure__,
            )
            forged.__annotations__ = original.__annotations__
            forged.__doc__ = original.__doc__
            forged.__module__ = original.__module__
            forged.__qualname__ = original.__qualname__
            module.Capability.apply = forged
            with self.assertRaisesRegex(
                PluginExecutableIdentityError,
                "method authority is unverifiable",
            ):
                plugin_identity._source_singleton_class_shape_identity(
                    module.Capability,
                    module=module,
                    module_name=module_name,
                    qualified_name="Capability",
                    source_path=source_path,
                    budget=plugin_identity._TargetIdentityBudget(),
                    scope_cache={},
                    depth=0,
                )
        finally:
            self._cleanup_modules(temporary, module_name)

    def test_module_target_with_native_leaf_is_stable_across_fresh_processes(
        self,
    ) -> None:
        module_name = "_rda_identity_native_leaf_factory"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "import json\n\n"
                    "def factory(request, configuration):\n"
                    "    return request, json.loads(configuration)\n"
                )
            },
            module_name,
        )
        try:
            expected = executable_module_target_fingerprint(
                module_name,
                "factory",
                module.factory,
            )
            script = (
                "import importlib\n"
                "from router_dump_analyzer.plugin_identity import "
                "executable_module_target_fingerprint\n"
                f"module = importlib.import_module({module_name!r})\n"
                "print(executable_module_target_fingerprint(\n"
                f"    {module_name!r}, 'factory', module.factory\n"
                "))\n"
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = os.pathsep.join(
                part
                for part in (
                    temporary.name,
                    environment.get("PYTHONPATH", ""),
                )
                if part
            )
            observed = tuple(
                subprocess.run(
                    [sys.executable, "-c", script],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    env=environment,
                ).stdout.strip()
                for _index in range(2)
            )
        finally:
            self._cleanup_modules(temporary, module_name)
        self.assertEqual(observed, (expected, expected))

    def test_function_owned_delegate_state_participates(self) -> None:
        module_name = "_rda_identity_function_state"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "def primary(value):\n"
                    "    return ('primary', value)\n\n"
                    "def alternate(value):\n"
                    "    return ('alternate', value)\n\n"
                    "def factory(request, configuration):\n"
                    "    return factory.delegate(request), configuration\n\n"
                    "factory.delegate = primary\n"
                )
            },
            module_name,
        )
        try:
            first = executable_module_target_fingerprint(
                module_name,
                "factory",
                module.factory,
            )
            module.factory.delegate = module.alternate
            second = executable_module_target_fingerprint(
                module_name,
                "factory",
                module.factory,
            )
        finally:
            self._cleanup_modules(temporary, module_name)
        self.assertNotEqual(first, second)

    def test_unloaded_local_import_dependency_fails_closed(self) -> None:
        helper_name = "_rda_identity_unloaded_helper"
        factory_name = "_rda_identity_unloaded_factory"
        temporary, (factory_module,) = self._import_modules(
            {
                helper_name: "def route(value):\n    return value\n",
                factory_name: (
                    "def factory(request, configuration):\n"
                    f"    import {helper_name} as helper\n"
                    "    return helper.route(request), configuration\n"
                ),
            },
            factory_name,
        )
        try:
            self.assertNotIn(helper_name, sys.modules)
            with self.assertRaisesRegex(
                PluginExecutableIdentityError,
                "not already exactly loaded",
            ):
                executable_module_target_fingerprint(
                    factory_name,
                    "factory",
                    factory_module.factory,
                )
        finally:
            self._cleanup_modules(temporary, helper_name, factory_name)

    def test_dynamic_import_api_fails_closed(self) -> None:
        module_name = "_rda_identity_dynamic_import"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "def factory(request, configuration):\n"
                    "    return __import__(configuration)\n"
                )
            },
            module_name,
        )
        try:
            with self.assertRaisesRegex(
                PluginExecutableIdentityError,
                "dynamic import API",
            ):
                executable_module_target_fingerprint(
                    module_name,
                    "factory",
                    module.factory,
                )
        finally:
            self._cleanup_modules(temporary, module_name)

    def test_same_process_callback_binds_closure_and_function_state(self) -> None:
        selected = "first"

        def primary(value: str) -> tuple[str, str]:
            return ("primary", value)

        def alternate(value: str) -> tuple[str, str]:
            return ("alternate", value)

        def callback(value: str) -> tuple[str, tuple[str, str]]:
            return (selected, callback.delegate(value))

        callback.delegate = primary  # type: ignore[attr-defined]
        first = executable_callable_fingerprint(callback)
        selected = "second"
        closure_changed = executable_callable_fingerprint(callback)
        callback.delegate = alternate  # type: ignore[attr-defined]
        delegate_changed = executable_callable_fingerprint(callback)
        self.assertNotEqual(first, closure_changed)
        self.assertNotEqual(closure_changed, delegate_changed)

    def test_same_process_callable_instance_binds_class_and_instance_state(self) -> None:
        class Callback:
            class_mode = "primary"

            def __init__(self) -> None:
                self.mode = "first"

            def __call__(self, value: str) -> tuple[str, str, str]:
                return (self.mode, Callback.class_mode, value)

        callback = Callback()
        first = executable_callable_fingerprint(callback)
        callback.mode = "second"
        instance_changed = executable_callable_fingerprint(callback)
        callback.mode = "first"
        Callback.class_mode = "alternate"
        class_changed = executable_callable_fingerprint(callback)
        self.assertNotEqual(first, instance_changed)
        self.assertNotEqual(first, class_changed)

    def test_same_process_binds_root_and_same_source_function_generations(
        self,
    ) -> None:
        module_name = "_rda_identity_same_source_function_generations"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "def helper(value):\n"
                    "    return ('helper', value)\n\n"
                    "def callback(value):\n"
                    "    return helper(value)\n"
                )
            },
            module_name,
        )
        try:
            first = executable_callable_fingerprint(module.callback)
            self.assertEqual(
                first,
                executable_callable_fingerprint(module.callback),
            )
            callback_clone = self._clone_function(module.callback)
            root_replaced = executable_callable_fingerprint(callback_clone)
            helper_clone = self._clone_function(module.helper)
            module.helper = helper_clone
            helper_rebound = executable_callable_fingerprint(module.callback)
        finally:
            self._cleanup_modules(temporary, module_name)
        self.assertNotEqual(first, root_replaced)
        self.assertNotEqual(first, helper_rebound)

    def test_same_process_binds_imported_function_and_class_generations(
        self,
    ) -> None:
        helper_name = "_rda_identity_external_authority_generations"
        callback_name = "_rda_identity_external_authority_callback"
        temporary, (helper, callback_module) = self._import_modules(
            {
                helper_name: (
                    "def route(value):\n"
                    "    return ('route', value)\n\n"
                    "class Dependency:\n"
                    "    @staticmethod\n"
                    "    def apply(value):\n"
                    "        return value\n\n"
                    "dependency = Dependency()\n"
                ),
                callback_name: (
                    f"import {helper_name} as helper\n\n"
                    "def callback(value):\n"
                    "    return helper.route(\n"
                    "        helper.dependency.apply(\n"
                    "            helper.Dependency.apply(value)\n"
                    "        )\n"
                    "    )\n"
                ),
            },
            helper_name,
            callback_name,
        )
        try:
            first = executable_callable_fingerprint(callback_module.callback)
            route_clone = self._clone_function(helper.route)
            helper.route = route_clone
            function_rebound = executable_callable_fingerprint(
                callback_module.callback
            )
            helper.dependency = helper.Dependency()
            receiver_rebound = executable_callable_fingerprint(
                callback_module.callback
            )
            dependency_clone = self._clone_class(helper.Dependency)
            helper.Dependency = dependency_clone
            class_rebound = executable_callable_fingerprint(
                callback_module.callback
            )
        finally:
            self._cleanup_modules(temporary, helper_name, callback_name)
        self.assertNotEqual(first, function_rebound)
        self.assertNotEqual(function_rebound, receiver_rebound)
        self.assertNotEqual(receiver_rebound, class_rebound)

    def test_same_process_binds_root_class_instance_and_bound_method_objects(
        self,
    ) -> None:
        module_name = "_rda_identity_root_authority_generations"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "class Callback:\n"
                    "    def __init__(self):\n"
                    "        self.mode = 'same'\n\n"
                    "    def __call__(self, value):\n"
                    "        return self.mode, value\n\n"
                    "    def method(self, value):\n"
                    "        return self.mode, value\n"
                )
            },
            module_name,
        )
        try:
            class_first = executable_callable_fingerprint(module.Callback)
            class_clone = self._clone_class(module.Callback)
            class_replaced = executable_callable_fingerprint(class_clone)

            callback = module.Callback()
            instance_first = executable_callable_fingerprint(callback)
            instance_replaced = executable_callable_fingerprint(module.Callback())

            bound = callback.method
            bound_first = executable_callable_fingerprint(bound)
            self.assertEqual(bound_first, executable_callable_fingerprint(bound))
            wrapper_replaced = executable_callable_fingerprint(callback.method)
            receiver_replaced = executable_callable_fingerprint(
                module.Callback().method
            )
        finally:
            self._cleanup_modules(temporary, module_name)
        self.assertNotEqual(class_first, class_replaced)
        self.assertNotEqual(instance_first, instance_replaced)
        self.assertNotEqual(bound_first, wrapper_replaced)
        self.assertNotEqual(wrapper_replaced, receiver_replaced)

    def test_same_process_binds_class_member_functions_and_descriptors(
        self,
    ) -> None:
        helper_name = "_rda_identity_class_member_generations"
        callback_name = "_rda_identity_class_member_callback"
        temporary, (helper, callback_module) = self._import_modules(
            {
                helper_name: (
                    "class Descriptor:\n"
                    "    def __get__(self, instance, owner):\n"
                    "        return 'marker'\n\n"
                    "    def __set__(self, instance, value):\n"
                    "        raise AttributeError('read only')\n\n"
                    "class Handler:\n"
                    "    marker = Descriptor()\n\n"
                    "    def apply(value):\n"
                    "        return value\n\n"
                    "    @classmethod\n"
                    "    def classify(cls, value):\n"
                    "        return value\n"
                ),
                callback_name: (
                    f"import {helper_name} as helper\n\n"
                    "def callback(value):\n"
                    "    return (\n"
                    "        helper.Handler.apply(value),\n"
                    "        helper.Handler.classify(value),\n"
                    "        helper.Handler.marker,\n"
                    "    )\n"
                ),
            },
            helper_name,
            callback_name,
        )
        try:
            first = executable_callable_fingerprint(callback_module.callback)
            method = vars(helper.Handler)["apply"]
            helper.Handler.apply = self._clone_function(method)
            method_replaced = executable_callable_fingerprint(
                callback_module.callback
            )

            classmethod_descriptor = vars(helper.Handler)["classify"]
            helper.Handler.classify = classmethod(classmethod_descriptor.__func__)
            classmethod_replaced = executable_callable_fingerprint(
                callback_module.callback
            )

            helper.Handler.marker = helper.Descriptor()
            descriptor_replaced = executable_callable_fingerprint(
                callback_module.callback
            )
        finally:
            self._cleanup_modules(temporary, helper_name, callback_name)
        self.assertNotEqual(first, method_replaced)
        self.assertNotEqual(method_replaced, classmethod_replaced)
        self.assertNotEqual(classmethod_replaced, descriptor_replaced)

    def test_external_class_wrappers_bound_non_function_callable_payloads(
        self,
    ) -> None:
        helper_name = "_rda_identity_external_wrapper_payloads"
        callback_name = "_rda_identity_external_wrapper_callback"
        temporary, (helper, callback_module) = self._import_modules(
            {
                helper_name: (
                    "import types\n\n"
                    "class Dependency:\n"
                    "    plain_alias = list[str]\n"
                    "    alias_type = types.GenericAlias\n"
                    "    static_alias = staticmethod(types.GenericAlias)\n"
                    "    class_alias = classmethod(types.GenericAlias)\n"
                ),
                callback_name: (
                    f"from {helper_name} import Dependency\n\n"
                    "def callback(value):\n"
                    "    return (\n"
                    "        Dependency.plain_alias(value),\n"
                    "        Dependency.alias_type(list, str)(value),\n"
                    "        Dependency.static_alias(list, str)(value),\n"
                    "        Dependency.class_alias(str)(value),\n"
                    "    )\n"
                ),
            },
            helper_name,
            callback_name,
        )
        helper = cast(ModuleType, helper)
        callback_module = cast(ModuleType, callback_module)

        def fingerprints() -> tuple[str, str]:
            return (
                executable_callable_fingerprint(callback_module.callback),
                executable_module_target_fingerprint(
                    callback_name,
                    "callback",
                    callback_module.callback,
                ),
            )

        try:
            first = fingerprints()
            self.assertEqual(first, fingerprints())
            helper.Dependency.static_alias = staticmethod(list[str])
            payload_replaced = fingerprints()
        finally:
            self._cleanup_modules(temporary, helper_name, callback_name)
        self.assertNotEqual(first[0], payload_replaced[0])
        self.assertNotEqual(first[1], payload_replaced[1])

    def test_dependency_class_wrappers_bound_non_function_callable_payloads(
        self,
    ) -> None:
        module_name = "_rda_identity_dependency_wrapper_payloads"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    f"import {module_name} as own\n"
                    "import types\n\n"
                    "class Dependency:\n"
                    "    static_alias = staticmethod(types.GenericAlias)\n"
                    "    class_alias = classmethod(types.GenericAlias)\n\n"
                    "class Capability:\n"
                    "    static_alias = staticmethod(types.GenericAlias)\n"
                    "    class_alias = classmethod(types.GenericAlias)\n\n"
                    "    def apply(self):\n"
                    "        return Dependency\n\n"
                    "capability = Capability()\n\n"
                    "def callback():\n"
                    "    return own.capability\n"
                )
            },
            module_name,
        )
        module = cast(ModuleType, module)

        def fingerprints() -> tuple[str, str]:
            return (
                executable_callable_fingerprint(module.callback),
                executable_module_target_fingerprint(
                    module_name,
                    "callback",
                    module.callback,
                ),
            )

        try:
            first = fingerprints()
            self.assertEqual(first, fingerprints())
            module.Dependency.class_alias = classmethod(cast(FunctionType, list[str]))
            payload_replaced = fingerprints()
        finally:
            self._cleanup_modules(temporary, module_name)
        self.assertNotEqual(first[0], payload_replaced[0])
        self.assertNotEqual(first[1], payload_replaced[1])

    def test_singleton_class_wrappers_reject_unsupported_payloads_cleanly(
        self,
    ) -> None:
        for wrapper in ("staticmethod", "classmethod"):
            module_name = f"_rda_identity_singleton_{wrapper}_payload"
            temporary, (module,) = self._import_modules(
                {
                    module_name: (
                        f"import {module_name} as own\n\n"
                        "class Capability:\n"
                        f"    unsupported = {wrapper}(object())\n\n"
                        "    def apply(self):\n"
                        "        return None\n\n"
                        "capability = Capability()\n\n"
                        "def callback():\n"
                        "    return own.capability\n"
                    )
                },
                module_name,
            )
            module = cast(ModuleType, module)
            try:
                for api in ("callable", "module-target"):
                    with (
                        self.subTest(wrapper=wrapper, api=api),
                        self.assertRaises(PluginExecutableIdentityError),
                    ):
                        if api == "callable":
                            executable_callable_fingerprint(module.callback)
                        else:
                            executable_module_target_fingerprint(
                                module_name,
                                "callback",
                                module.callback,
                            )
            finally:
                self._cleanup_modules(temporary, module_name)

    def test_singleton_class_wrapper_subclasses_cannot_run_attribute_traps(
        self,
    ) -> None:
        wrappers = {
            "staticmethod": ("__func__", "lambda: None"),
            "classmethod": ("__func__", "lambda cls: None"),
            "property": ("fget", "lambda self: None"),
        }
        for wrapper, (trapped_attribute, payload) in wrappers.items():
            module_name = f"_rda_identity_hostile_{wrapper}_subclass"
            temporary, (module,) = self._import_modules(
                {
                    module_name: (
                        f"import {module_name} as own\n\n"
                        f"class Hostile({wrapper}):\n"
                        "    def __getattribute__(self, name):\n"
                        f"        if name == {trapped_attribute!r}:\n"
                        "            raise RuntimeError('descriptor trap')\n"
                        "        return super().__getattribute__(name)\n\n"
                        "class Capability:\n"
                        f"    trapped = Hostile({payload})\n\n"
                        "    def apply(self):\n"
                        "        return None\n\n"
                        "capability = Capability()\n\n"
                        "def callback():\n"
                        "    return own.capability\n"
                    )
                },
                module_name,
            )
            module = cast(ModuleType, module)
            try:
                for api in ("callable", "module-target"):
                    with (
                        self.subTest(wrapper=wrapper, api=api),
                        self.assertRaisesRegex(
                            PluginExecutableIdentityError,
                            "descriptor-wrapper subclass is unsupported",
                        ),
                    ):
                        if api == "callable":
                            executable_callable_fingerprint(module.callback)
                        else:
                            executable_module_target_fingerprint(
                                module_name,
                                "callback",
                                module.callback,
                            )
            finally:
                self._cleanup_modules(temporary, module_name)

    def test_external_function_walkers_reject_non_function_payloads(self) -> None:
        payload = cast(FunctionType, plugin_identity.GenericAlias)
        budget = plugin_identity._TargetIdentityBudget()
        with self.assertRaisesRegex(
            PluginExecutableIdentityError,
            "external function is not an exact Python function",
        ):
            plugin_identity._external_function_leaf_identity(
                payload,
                module=cast(ModuleType, sys.modules["types"]),
                module_name="types",
                qualified_name="GenericAlias",
                source_path=Path(__file__),
                budget=budget,
                scope_cache={},
                callable_cache={},
                active_callables=set(),
                identity_root=__name__,
                depth=0,
            )
        with self.assertRaisesRegex(
            PluginExecutableIdentityError,
            "external class member is not an exact Python function",
        ):
            plugin_identity._update_external_class_member_function(
                hashlib.sha256(),
                payload,
                label="static-method",
                budget=budget,
                scope_cache={},
                callable_cache={},
                active_callables=set(),
                identity_root=__name__,
                depth=0,
            )

    def test_module_target_clone_rebinding_is_token_free_and_deterministic(
        self,
    ) -> None:
        module_name = "_rda_identity_module_target_clone_rebinding"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "def helper(value):\n"
                    "    return ('helper', value)\n\n"
                    "def callback(value):\n"
                    "    return helper(value)\n"
                )
            },
            module_name,
        )
        try:
            with patch.object(
                plugin_identity,
                "_update_retained_capability_token",
                side_effect=AssertionError("module target requested a token"),
            ):
                first = executable_module_target_fingerprint(
                    module_name,
                    "callback",
                    module.callback,
                )
                callback_clone = self._clone_function(module.callback)
                module.callback = callback_clone
                callback_rebound = executable_module_target_fingerprint(
                    module_name,
                    "callback",
                    callback_clone,
                )
                module.helper = self._clone_function(module.helper)
                helper_rebound = executable_module_target_fingerprint(
                    module_name,
                    "callback",
                    callback_clone,
                )
            script = (
                "import importlib\n"
                "from router_dump_analyzer.plugin_identity import "
                "executable_module_target_fingerprint\n"
                f"module = importlib.import_module({module_name!r})\n"
                "print(executable_module_target_fingerprint(\n"
                f"    {module_name!r}, 'callback', module.callback\n"
                "))\n"
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = os.pathsep.join(
                part
                for part in (
                    temporary.name,
                    environment.get("PYTHONPATH", ""),
                )
                if part
            )
            observed = subprocess.run(
                [sys.executable, "-c", script],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
                env=environment,
            ).stdout.strip()
        finally:
            self._cleanup_modules(temporary, module_name)
        self.assertEqual(first, callback_rebound)
        self.assertEqual(first, helper_rebound)
        self.assertEqual(first, observed)

    def test_same_process_callback_accepts_volatile_sync_capabilities(self) -> None:
        entered = threading.Event()
        guard = threading.Lock()

        def callback(value: str) -> tuple[str, bool]:
            with guard:
                entered.set()
                return (value, entered.is_set())

        first = executable_callable_fingerprint(callback)
        entered.set()
        with guard:
            second = executable_callable_fingerprint(callback)
        self.assertEqual(first, second)
        entered = threading.Event()
        event_replaced = executable_callable_fingerprint(callback)
        self.assertNotEqual(second, event_replaced)
        guard = threading.Lock()
        lock_replaced = executable_callable_fingerprint(callback)
        self.assertNotEqual(event_replaced, lock_replaced)

    def test_same_process_callback_binds_exact_global_native_lock(self) -> None:
        module_name = "_rda_identity_global_native_lock"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "import threading\n\n"
                    "guard = threading.Lock()\n\n"
                    "def callback(value):\n"
                    "    with guard:\n"
                    "        return value\n"
                )
            },
            module_name,
        )
        try:
            actual_id = id
            lock_type = type(module.guard)

            def forced_reused_id(value: object) -> int:
                if type(value) is lock_type:
                    return 1
                return actual_id(value)

            with patch.object(
                plugin_identity,
                "id",
                new=forced_reused_id,
                create=True,
            ):
                first = executable_callable_fingerprint(module.callback)
                with module.guard:
                    state_changed = executable_callable_fingerprint(module.callback)
                module.guard = threading.Lock()
                replacement = executable_callable_fingerprint(module.callback)
        finally:
            self._cleanup_modules(temporary, module_name)
        self.assertEqual(first, state_changed)
        self.assertNotEqual(first, replacement)

    def test_same_process_callback_binds_exact_external_dependency_instance(
        self,
    ) -> None:
        helper_name = "_rda_identity_external_dependency"
        callback_name = "_rda_identity_external_dependency_callback"
        temporary, (helper, callback_module) = self._import_modules(
            {
                helper_name: (
                    "class Dependency:\n"
                    "    def __init__(self):\n"
                    "        self.mode = 'primary'\n\n"
                    "    def apply(self, value):\n"
                    "        return self.mode, value\n\n"
                    "dependency = Dependency()\n"
                ),
                callback_name: (
                    f"from {helper_name} import dependency\n\n"
                    "def callback(value):\n"
                    "    return dependency.apply(value)\n"
                ),
            },
            helper_name,
            callback_name,
        )
        try:
            actual_id = id

            def forced_reused_id(value: object) -> int:
                if type(value) is helper.Dependency:
                    return 1
                return actual_id(value)

            with patch.object(
                plugin_identity,
                "id",
                new=forced_reused_id,
                create=True,
            ):
                first = executable_callable_fingerprint(callback_module.callback)
                callback_module.dependency.mode = "alternate"
                state_changed = executable_callable_fingerprint(
                    callback_module.callback
                )
                replacement_dependency = helper.Dependency()
                callback_module.dependency = replacement_dependency
                helper.dependency = replacement_dependency
                replacement = executable_callable_fingerprint(
                    callback_module.callback
                )
        finally:
            self._cleanup_modules(temporary, helper_name, callback_name)
        self.assertEqual(first, state_changed)
        self.assertNotEqual(first, replacement)

    def test_same_process_callback_binds_nested_external_class_members(
        self,
    ) -> None:
        helper_name = "_rda_identity_nested_external_class"
        callback_name = "_rda_identity_nested_external_class_callback"
        temporary, (helper, callback_module) = self._import_modules(
            {
                helper_name: (
                    "import threading\n\n"
                    "class Delegate:\n"
                    "    def __init__(self):\n"
                    "        self.mode = 'primary'\n\n"
                    "    def apply(self, value):\n"
                    "        return self.mode, value\n\n"
                    "class Dependency:\n"
                    "    class Authority:\n"
                    "        guard = threading.Lock()\n"
                    "        delegate = Delegate()\n\n"
                    "    @classmethod\n"
                    "    def apply(cls, value):\n"
                    "        with cls.Authority.guard:\n"
                    "            return cls.Authority.delegate.apply(value)\n"
                ),
                callback_name: (
                    f"from {helper_name} import Dependency\n\n"
                    "def callback(value):\n"
                    "    return Dependency.apply(value)\n"
                ),
            },
            helper_name,
            callback_name,
        )
        try:
            actual_id = id
            lock_type = type(helper.Dependency.Authority.guard)

            def forced_reused_id(value: object) -> int:
                if type(value) in {lock_type, helper.Delegate}:
                    return 1
                return actual_id(value)

            with patch.object(
                plugin_identity,
                "id",
                new=forced_reused_id,
                create=True,
            ):
                first = executable_callable_fingerprint(callback_module.callback)
                helper.Dependency.Authority.delegate.mode = "alternate"
                with helper.Dependency.Authority.guard:
                    state_changed = executable_callable_fingerprint(
                        callback_module.callback
                    )
                helper.Dependency.Authority.guard = threading.Lock()
                lock_replaced = executable_callable_fingerprint(
                    callback_module.callback
                )
                helper.Dependency.Authority.delegate = helper.Delegate()
                delegate_replaced = executable_callable_fingerprint(
                    callback_module.callback
                )
        finally:
            self._cleanup_modules(temporary, helper_name, callback_name)
        self.assertEqual(first, state_changed)
        self.assertNotEqual(first, lock_replaced)
        self.assertNotEqual(lock_replaced, delegate_replaced)

    def test_module_target_external_class_members_are_process_stable_without_tokens(
        self,
    ) -> None:
        helper_name = "_rda_identity_process_stable_external_class"
        callback_name = "_rda_identity_process_stable_external_class_callback"
        temporary, (_helper, callback_module) = self._import_modules(
            {
                helper_name: (
                    "import threading\n\n"
                    "class Delegate:\n"
                    "    def apply(self, value):\n"
                    "        return value\n\n"
                    "class Dependency:\n"
                    "    guard = threading.Lock()\n"
                    "    delegate = Delegate()\n"
                ),
                callback_name: (
                    f"from {helper_name} import Dependency\n\n"
                    "def callback(value):\n"
                    "    with Dependency.guard:\n"
                    "        return Dependency.delegate.apply(value)\n"
                ),
            },
            helper_name,
            callback_name,
        )
        try:
            with plugin_identity._RETAINED_CAPABILITY_TOKEN_LOCK:
                before = (
                    dict(plugin_identity._RETAINED_CAPABILITY_WEAK_TOKENS),
                    dict(plugin_identity._RETAINED_CAPABILITY_STRONG_TOKENS),
                )
            expected = executable_module_target_fingerprint(
                callback_name,
                "callback",
                callback_module.callback,
            )
            with plugin_identity._RETAINED_CAPABILITY_TOKEN_LOCK:
                after = (
                    dict(plugin_identity._RETAINED_CAPABILITY_WEAK_TOKENS),
                    dict(plugin_identity._RETAINED_CAPABILITY_STRONG_TOKENS),
                )
            script = (
                "import importlib\n"
                "from router_dump_analyzer.plugin_identity import "
                "executable_module_target_fingerprint\n"
                f"module = importlib.import_module({callback_name!r})\n"
                "print(executable_module_target_fingerprint(\n"
                f"    {callback_name!r}, 'callback', module.callback\n"
                "))\n"
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = os.pathsep.join(
                part
                for part in (
                    temporary.name,
                    environment.get("PYTHONPATH", ""),
                )
                if part
            )
            observed = subprocess.run(
                [sys.executable, "-c", script],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
                env=environment,
            ).stdout.strip()
        finally:
            self._cleanup_modules(temporary, helper_name, callback_name)
        self.assertEqual(before, after)
        self.assertEqual(expected, observed)

    def test_inherited_and_metaclass_call_replacements_change_callback_seals(
        self,
    ) -> None:
        module_name = "_rda_identity_dependency_call_authority"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "class Base:\n"
                    "    def __call__(self, value):\n"
                    "        return ('base', value)\n\n"
                    "class Callback(Base):\n"
                    "    pass\n\n"
                    "def alternate_instance_call(self, value):\n"
                    "    return ('alternate-base', value)\n\n"
                    "callback = Callback()\n\n"
                    "class Meta(type):\n"
                    "    def __call__(cls, value):\n"
                    "        return ('meta', value)\n\n"
                    "class Factory(metaclass=Meta):\n"
                    "    pass\n\n"
                    "def alternate_meta_call(cls, value):\n"
                    "    return ('alternate-meta', value)\n"
                )
            },
            module_name,
        )
        try:
            base_call = vars(module.Base)["__call__"]
            callback_first = executable_callable_fingerprint(module.callback)
            callback_target_first = executable_module_target_fingerprint(
                module_name,
                "callback",
                module.callback,
            )
            module.Base.__call__ = module.alternate_instance_call
            callback_different = executable_callable_fingerprint(module.callback)
            callback_target_different = executable_module_target_fingerprint(
                module_name,
                "callback",
                module.callback,
            )
            module.Base.__call__ = self._clone_function(base_call)
            callback_clone = executable_callable_fingerprint(module.callback)
            callback_target_clone = executable_module_target_fingerprint(
                module_name,
                "callback",
                module.callback,
            )

            meta_call = vars(module.Meta)["__call__"]
            metaclass_first = executable_callable_fingerprint(module.Factory)
            metaclass_target_first = executable_module_target_fingerprint(
                module_name,
                "Factory",
                module.Factory,
            )
            module.Meta.__call__ = module.alternate_meta_call
            metaclass_different = executable_callable_fingerprint(module.Factory)
            metaclass_target_different = executable_module_target_fingerprint(
                module_name,
                "Factory",
                module.Factory,
            )
            module.Meta.__call__ = self._clone_function(meta_call)
            metaclass_clone = executable_callable_fingerprint(module.Factory)
            metaclass_target_clone = executable_module_target_fingerprint(
                module_name,
                "Factory",
                module.Factory,
            )
        finally:
            self._cleanup_modules(temporary, module_name)
        self.assertNotEqual(callback_first, callback_different)
        self.assertNotEqual(callback_first, callback_clone)
        self.assertNotEqual(callback_target_first, callback_target_different)
        self.assertEqual(callback_target_first, callback_target_clone)
        self.assertNotEqual(metaclass_first, metaclass_different)
        self.assertNotEqual(metaclass_first, metaclass_clone)
        self.assertNotEqual(metaclass_target_first, metaclass_target_different)
        self.assertEqual(metaclass_target_first, metaclass_target_clone)

    def test_external_inherited_constructor_binds_full_function_runtime(self) -> None:
        routes_name = "_rda_identity_constructor_routes"
        dependency_name = "_rda_identity_constructor_dependency"
        callback_name = "_rda_identity_constructor_callback"
        temporary, (routes, dependency, callback_module) = self._import_modules(
            {
                routes_name: (
                    "def primary(value):\n"
                    "    return ('import-primary', value)\n\n"
                    "def alternate(value):\n"
                    "    return ('import-alternate', value)\n\n"
                    "route = primary\n"
                ),
                dependency_name: (
                    f"import {routes_name} as imported_routes\n\n"
                    "def primary(value):\n"
                    "    return ('primary', value)\n\n"
                    "def alternate(value):\n"
                    "    return ('alternate', value)\n\n"
                    "route = primary\n\n"
                    "class Settings:\n"
                    "    delegate = primary\n\n"
                    "def make_base():\n"
                    "    closure_delegate = [primary]\n\n"
                    "    class Base:\n"
                    "        def __init__(self, value, *, keyword_delegate=primary):\n"
                    f"            import {routes_name} as local_routes\n"
                    "            self.value = (\n"
                    "                closure_delegate[0](value),\n"
                    "                keyword_delegate(value),\n"
                    "                route(value),\n"
                    "                Settings.delegate(value),\n"
                    "                local_routes.route(value),\n"
                    "                Base.__init__.owned_delegate(value),\n"
                    "            )\n\n"
                    "    Base.__name__ = 'Base'\n"
                    "    Base.__qualname__ = 'Base'\n"
                    "    Base.__init__.owned_delegate = primary\n"
                    "    return Base, closure_delegate\n\n"
                    "Base, closure_delegate = make_base()\n\n"
                    "class Dependency(Base):\n"
                    "    pass\n"
                ),
                callback_name: (
                    f"from {dependency_name} import Dependency\n\n"
                    "def callback(value):\n"
                    "    return Dependency(value).value\n"
                ),
            },
            routes_name,
            dependency_name,
            callback_name,
        )

        def fingerprints() -> tuple[str, str]:
            return (
                executable_callable_fingerprint(callback_module.callback),
                executable_module_target_fingerprint(
                    callback_name,
                    "callback",
                    callback_module.callback,
                ),
            )

        try:
            identities = [fingerprints()]
            dependency.closure_delegate[0] = dependency.alternate
            identities.append(fingerprints())
            vars(dependency.Base)["__init__"].__kwdefaults__[  # type: ignore[index]
                "keyword_delegate"
            ] = dependency.alternate
            identities.append(fingerprints())
            dependency.route = dependency.alternate
            identities.append(fingerprints())
            dependency.Settings.delegate = dependency.alternate
            identities.append(fingerprints())
            routes.route = routes.alternate
            identities.append(fingerprints())
            vars(dependency.Base)["__init__"].owned_delegate = dependency.alternate
            identities.append(fingerprints())
        finally:
            self._cleanup_modules(
                temporary,
                routes_name,
                dependency_name,
                callback_name,
            )
        for previous, current in pairwise(identities):
            self.assertNotEqual(previous[0], current[0])
            self.assertNotEqual(previous[1], current[1])

    def test_abc_identity_ignores_derived_subclass_caches(self) -> None:
        module_name = "_rda_identity_abc_registry"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "from abc import ABC\n\n"
                    "class Contract(ABC):\n"
                    "    pass\n\n"
                    "class Concrete(Contract):\n"
                    "    pass\n\n"
                    "class Unrelated:\n"
                    "    pass\n"
                )
            },
            module_name,
        )

        def fingerprints() -> tuple[str, str]:
            return (
                executable_callable_fingerprint(module.Contract),
                executable_module_target_fingerprint(
                    module_name,
                    "Contract",
                    module.Contract,
                ),
            )

        try:
            first = fingerprints()
            self.assertTrue(issubclass(module.Concrete, module.Contract))
            positive_cache = fingerprints()
            self.assertFalse(issubclass(module.Unrelated, module.Contract))
            negative_cache = fingerprints()
            module.Contract.register(module.Unrelated)
            registered = fingerprints()
        finally:
            self._cleanup_modules(temporary, module_name)
        self.assertEqual(first, positive_cache)
        self.assertEqual(first, negative_cache)
        self.assertNotEqual(first, registered)

    def test_abc_registry_binds_re_registered_class_generation(self) -> None:
        module_name = "_rda_identity_abc_generation"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "from abc import ABC\n\n"
                    "class Contract(ABC):\n"
                    "    pass\n\n"
                    "class Registered:\n"
                    "    pass\n\n"
                    "Contract.register(Registered)\n\n"
                    "def accepts(value):\n"
                    "    return isinstance(value, Contract)\n"
                )
            },
            module_name,
        )
        module = cast(ModuleType, module)
        try:
            retained_before = executable_callable_fingerprint(module.accepts)
            executable_module_target_fingerprint(
                module_name,
                "Contract",
                module.Contract,
            )
            replacement = type(
                "Registered",
                (),
                {
                    "__module__": module_name,
                    "__qualname__": "Registered",
                },
            )
            delattr(module, "Registered")
            gc.collect()
            module.Contract.register(replacement)

            retained_after = executable_callable_fingerprint(module.accepts)
            self.assertNotEqual(retained_before, retained_after)
            self.assertTrue(issubclass(replacement, module.Contract))
            with self.assertRaisesRegex(
                PluginExecutableIdentityError,
                "abstract class registry member has no exact static provenance",
            ):
                executable_module_target_fingerprint(
                    module_name,
                    "Contract",
                    module.Contract,
                )
        finally:
            self._cleanup_modules(temporary, module_name)

    def test_abc_registry_rejects_equal_distinct_replacement_during_sort(
        self,
    ) -> None:
        module_name = "_rda_identity_abc_equal_registration"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "from abc import ABC, ABCMeta\n\n"
                    "class EqualMeta(ABCMeta):\n"
                    "    def __eq__(cls, other):\n"
                    "        return isinstance(other, EqualMeta)\n\n"
                    "    def __hash__(cls):\n"
                    "        return 7\n\n"
                    "class Contract(ABC):\n"
                    "    pass\n\n"
                    "class Registered(metaclass=EqualMeta):\n"
                    "    pass\n\n"
                    "class Replacement(metaclass=EqualMeta):\n"
                    "    pass\n\n"
                    "Contract.register(Registered)\n"
                )
            },
            module_name,
        )
        module = cast(ModuleType, module)
        operations = {
            "same-process": lambda: executable_callable_fingerprint(
                module.Contract
            ),
            "module-target": lambda: executable_module_target_fingerprint(
                module_name,
                "Contract",
                module.Contract,
            ),
        }
        actual_sorted = sorted
        try:
            self.assertIsNot(module.Registered, module.Replacement)
            self.assertEqual(module.Registered, module.Replacement)
            self.assertEqual(hash(module.Registered), hash(module.Replacement))
            for label, operation in operations.items():
                with self.subTest(path=label):
                    abc._reset_registry(module.Contract)
                    abc._reset_caches(module.Contract)
                    module.Contract.register(module.Registered)
                    mutated = False

                    def mutate_during_registry_sort(
                        values: object,
                        *args: object,
                        **kwargs: object,
                    ):
                        nonlocal mutated
                        snapshot = tuple(values)  # type: ignore[arg-type]
                        if not mutated and any(
                            type(item) is tuple
                            and len(item) == 4
                            and item[0] == module_name
                            and item[1] == "Registered"
                            for item in snapshot
                        ):
                            mutated = True
                            abc._reset_registry(module.Contract)
                            abc._reset_caches(module.Contract)
                            module.Contract.register(module.Replacement)
                        return actual_sorted(  # type: ignore[arg-type]
                            snapshot,
                            *args,
                            **kwargs,
                        )

                    with (
                        patch.object(
                            plugin_identity,
                            "sorted",
                            new=mutate_during_registry_sort,
                            create=True,
                        ),
                        self.assertRaisesRegex(
                            PluginExecutableIdentityError,
                            "abstract class registry changed while fingerprinting",
                        ),
                    ):
                        operation()
                    self.assertTrue(mutated)
        finally:
            self._cleanup_modules(temporary, module_name)

    def test_exact_snapshot_verifiers_reject_equal_distinct_objects(self) -> None:
        class EqualKey:
            def __eq__(self, other: object) -> bool:
                return isinstance(other, EqualKey)

            def __hash__(self) -> int:
                return 11

        original = EqualKey()
        replacement = EqualKey()
        retained_value = object()
        self.assertIsNot(original, replacement)
        self.assertEqual(original, replacement)

        mapping = {original: retained_value}
        mapping_snapshot = tuple(mapping.items())
        del mapping[original]
        mapping[replacement] = retained_value
        with self.assertRaisesRegex(
            PluginExecutableIdentityError,
            "runtime mapping changed while fingerprinting",
        ):
            plugin_identity._verify_dict_snapshot(mapping, mapping_snapshot)

        backing = {original: retained_value}
        proxy = MappingProxyType(backing)
        proxy_snapshot = tuple(proxy.items())
        del backing[original]
        backing[replacement] = retained_value
        with self.assertRaisesRegex(
            PluginExecutableIdentityError,
            "mapping proxy changed while fingerprinting",
        ):
            plugin_identity._verify_exact_mapping_snapshot(
                proxy,
                proxy_snapshot,
                label="module target mapping proxy",
            )

        self.assertFalse(
            plugin_identity._same_exact_unordered_objects(
                (replacement,),
                (original,),
            )
        )

    def test_module_target_accepts_exact_owned_descriptor_accessors(self) -> None:
        module_name = "_rda_identity_custom_coordinator_descriptor"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "from router_dump_analyzer.ingestion import "
                    "IngestionCoordinator\n\n"
                    "class CustomCoordinator(IngestionCoordinator):\n"
                    "    marker = 'stable'\n\n"
                    "coordinator = CustomCoordinator()\n"
                )
            },
            module_name,
        )
        module = cast(ModuleType, module)
        try:
            first = executable_module_target_fingerprint(
                module_name,
                "coordinator",
                module.coordinator,
            )
            second = executable_module_target_fingerprint(
                module_name,
                "coordinator",
                module.coordinator,
            )
        finally:
            self._cleanup_modules(temporary, module_name)
        self.assertEqual(first, second)
        self.assertRegex(first, r"\Atarget-sha256:[0-9a-f]{64}\Z")

    def test_module_target_accepts_owned_dynamic_and_general_descriptors(
        self,
    ) -> None:
        module_name = "_rda_identity_owned_descriptor_kinds"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "from types import DynamicClassAttribute\n\n"
                    "class GeneralDescriptor:\n"
                    "    def __init__(self, fget, fset=None, fdel=None):\n"
                    "        self.fget = fget\n"
                    "        self.fset = fset\n"
                    "        self.fdel = fdel\n\n"
                    "    def __get__(self, instance, owner):\n"
                    "        return self if instance is None else self.fget(instance)\n\n"
                    "    def getter(self, function):\n"
                    "        return type(self)(function, self.fset, self.fdel)\n\n"
                    "    def setter(self, function):\n"
                    "        return type(self)(self.fget, function, self.fdel)\n\n"
                    "    def deleter(self, function):\n"
                    "        return type(self)(self.fget, self.fset, function)\n\n"
                    "class Owner:\n"
                    "    @DynamicClassAttribute\n"
                    "    def dynamic(self):\n"
                    "        return 1\n\n"
                    "    @dynamic.setter\n"
                    "    def dynamic(self, value):\n"
                    "        self._dynamic = value\n\n"
                    "    @dynamic.deleter\n"
                    "    def dynamic(self):\n"
                    "        del self._dynamic\n\n"
                    "    @GeneralDescriptor\n"
                    "    def general(self):\n"
                    "        return 2\n\n"
                    "    @general.setter\n"
                    "    def general(self, value):\n"
                    "        self._general = value\n\n"
                    "    @general.deleter\n"
                    "    def general(self):\n"
                    "        del self._general\n\n"
                    "def callback():\n"
                    "    return (Owner.dynamic, Owner.general)\n"
                )
            },
            module_name,
        )
        module = cast(ModuleType, module)
        try:
            first = executable_module_target_fingerprint(
                module_name,
                "callback",
                module.callback,
            )
            second = executable_module_target_fingerprint(
                module_name,
                "callback",
                module.callback,
            )
        finally:
            self._cleanup_modules(temporary, module_name)
        self.assertEqual(first, second)

    def test_module_target_rejects_unowned_descriptor_alias(self) -> None:
        module_name = "_rda_identity_descriptor_alias"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "from enum import Enum\n\n"
                    "value_descriptor = vars(Enum)['value']\n\n"
                    "def callback():\n"
                    "    return value_descriptor\n"
                )
            },
            module_name,
        )
        module = cast(ModuleType, module)
        try:
            with self.assertRaisesRegex(
                PluginExecutableIdentityError,
                "unowned descriptor alias",
            ):
                executable_module_target_fingerprint(
                    module_name,
                    "callback",
                    module.callback,
                )
        finally:
            self._cleanup_modules(temporary, module_name)

    def test_owned_descriptor_replacement_during_attestation_fails_closed(
        self,
    ) -> None:
        module_name = "_rda_identity_descriptor_mutation"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "class Owner:\n"
                    "    @property\n"
                    "    def value(self):\n"
                    "        return 1\n\n"
                    "def replacement(self):\n"
                    "    return 2\n\n"
                    "def callback():\n"
                    "    return Owner.value\n"
                )
            },
            module_name,
        )
        module = cast(ModuleType, module)
        descriptor = vars(module.Owner)["value"]
        accessor = descriptor.fget
        actual_function_identity = plugin_identity._function_runtime_identity
        mutated = False

        def mutate_owned_descriptor(function: object, *args: object, **kwargs: object):
            nonlocal mutated
            budget = kwargs.get("budget")
            if (
                not mutated
                and function is accessor
                and isinstance(budget, plugin_identity._TargetIdentityBudget)
                and budget.owned_descriptor_accessors.get(id(function))
            ):
                mutated = True
                module.Owner.value = property(module.replacement)
            return actual_function_identity(  # type: ignore[arg-type]
                function,
                *args,
                **kwargs,
            )

        try:
            with (
                patch.object(
                    plugin_identity,
                    "_function_runtime_identity",
                    new=mutate_owned_descriptor,
                ),
                self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "descriptor changed while fingerprinting",
                ),
            ):
                executable_module_target_fingerprint(
                    module_name,
                    "callback",
                    module.callback,
                )
            self.assertTrue(mutated)
        finally:
            module.Owner.value = descriptor
            self._cleanup_modules(temporary, module_name)

    def test_declared_source_rewrite_during_attestation_fails_closed(self) -> None:
        module_name = "_rda_identity_declared_source_rewrite"
        original_source = "def callback():\n    return 'A'\n"
        changed_source = "def callback():\n    return 'B'\n"
        temporary, (module,) = self._import_modules(
            {module_name: original_source},
            module_name,
        )
        module = cast(ModuleType, module)
        actual_declared_code_objects = plugin_identity._declared_code_objects
        mutated = False

        def rewrite_after_cache_fill(
            *,
            module_name: str,
            qualified_name: str,
            source_path: Path,
            budget: plugin_identity._TargetIdentityBudget,
        ) -> tuple[CodeType, ...]:
            nonlocal mutated
            result = actual_declared_code_objects(
                module_name=module_name,
                qualified_name=qualified_name,
                source_path=source_path,
                budget=budget,
            )
            if not mutated:
                mutated = True
                source_path.write_text(changed_source, encoding="utf-8")
            return result

        try:
            with (
                patch.object(
                    plugin_identity,
                    "_declared_code_objects",
                    new=rewrite_after_cache_fill,
                ),
                self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "source changed while fingerprinting",
                ),
            ):
                executable_module_target_fingerprint(
                    module_name,
                    "callback",
                    module.callback,
                )
            self.assertTrue(mutated)
        finally:
            self._cleanup_modules(temporary, module_name)

    def test_declared_source_deletion_during_attestation_fails_closed(self) -> None:
        module_name = "_rda_identity_declared_source_delete"
        temporary, (module,) = self._import_modules(
            {module_name: "def callback():\n    return 'A'\n"},
            module_name,
        )
        module = cast(ModuleType, module)
        actual_declared_code_objects = plugin_identity._declared_code_objects
        mutated = False

        def delete_after_cache_fill(
            *,
            module_name: str,
            qualified_name: str,
            source_path: Path,
            budget: plugin_identity._TargetIdentityBudget,
        ) -> tuple[CodeType, ...]:
            nonlocal mutated
            result = actual_declared_code_objects(
                module_name=module_name,
                qualified_name=qualified_name,
                source_path=source_path,
                budget=budget,
            )
            if not mutated:
                mutated = True
                source_path.unlink()
            return result

        try:
            with (
                patch.object(
                    plugin_identity,
                    "_declared_code_objects",
                    new=delete_after_cache_fill,
                ),
                self.assertRaises(PluginExecutableIdentityError),
            ):
                executable_module_target_fingerprint(
                    module_name,
                    "callback",
                    module.callback,
                )
            self.assertTrue(mutated)
        finally:
            self._cleanup_modules(temporary, module_name)

    def test_declared_source_same_bytes_replacement_fails_closed(self) -> None:
        module_name = "_rda_identity_declared_source_replace"
        temporary, (module,) = self._import_modules(
            {module_name: "def callback():\n    return 'A'\n"},
            module_name,
        )
        module = cast(ModuleType, module)
        source_path = Path(cast(str, module.__file__)).resolve(strict=True)
        original_source = source_path.read_bytes()
        initial_stat_identity = plugin_identity._stat_identity(source_path.lstat())
        actual_declared_code_objects = plugin_identity._declared_code_objects
        replacement_stat_identity: tuple[int, int, int, int, int] | None = None

        def replace_after_cache_fill(
            *,
            module_name: str,
            qualified_name: str,
            source_path: Path,
            budget: plugin_identity._TargetIdentityBudget,
        ) -> tuple[CodeType, ...]:
            nonlocal replacement_stat_identity
            result = actual_declared_code_objects(
                module_name=module_name,
                qualified_name=qualified_name,
                source_path=source_path,
                budget=budget,
            )
            if replacement_stat_identity is None:
                replacement_path = source_path.with_name(
                    f"{source_path.name}.replacement"
                )
                replacement_path.write_bytes(original_source)
                os.replace(replacement_path, source_path)
                replacement_stat_identity = plugin_identity._stat_identity(
                    source_path.lstat()
                )
            return result

        try:
            with (
                patch.object(
                    plugin_identity,
                    "_declared_code_objects",
                    new=replace_after_cache_fill,
                ),
                self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "source changed while fingerprinting",
                ),
            ):
                executable_module_target_fingerprint(
                    module_name,
                    "callback",
                    module.callback,
                )
            self.assertIsNotNone(replacement_stat_identity)
            self.assertNotEqual(initial_stat_identity, replacement_stat_identity)
        finally:
            self._cleanup_modules(temporary, module_name)

    def test_declared_source_batch_cache_compiles_one_exact_snapshot(self) -> None:
        module_name = "_rda_identity_declared_source_batch"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "def first():\n"
                    "    return 'first'\n\n"
                    "def second():\n"
                    "    return 'second'\n"
                )
            },
            module_name,
        )
        module = cast(ModuleType, module)
        source_path = Path(cast(str, module.__file__)).resolve(strict=True)
        batch_cache: dict[
            tuple[str, Path, str], tuple[CodeType, ...]
        ] = {}
        try:
            with patch.object(
                plugin_identity,
                "compile",
                wraps=compile,
                create=True,
            ) as compile_source:
                first = executable_module_target_fingerprint(
                    module_name,
                    "first",
                    module.first,
                    _batch_declared_code_cache=batch_cache,
                )
                second = executable_module_target_fingerprint(
                    module_name,
                    "second",
                    module.second,
                    _batch_declared_code_cache=batch_cache,
                )
            self.assertEqual(compile_source.call_count, 1)
            self.assertEqual(len(batch_cache), 1)
            cache_module_name, cache_source_path, cache_source_identity = next(
                iter(batch_cache)
            )
            self.assertEqual(cache_module_name, module_name)
            self.assertEqual(cache_source_path, source_path)
            self.assertRegex(cache_source_identity, r"\A[0-9a-f]{64}\Z")
            self.assertNotEqual(first, second)
        finally:
            self._cleanup_modules(temporary, module_name)

    def test_external_function_dependency_analysis_is_linear_and_verified(
        self,
    ) -> None:
        for size in (32, 64, 128):
            module_name = f"_rda_identity_dependency_cache_{size}"
            values = "\n".join(
                f"value_{index} = object()" for index in range(size)
            )
            defaults = ", ".join(
                f"argument_{index}=value_{index}" for index in range(size)
            )
            references = ", ".join(f"value_{index}" for index in range(size))
            temporary, (module,) = self._import_modules(
                {
                    module_name: (
                        f"{values}\n\n"
                        f"def callback({defaults}):\n"
                        f"    return ({references})\n\n"
                        "def replacement():\n"
                        "    return None\n"
                    )
                },
                module_name,
            )
            module = cast(ModuleType, module)
            try:
                budget = plugin_identity._TargetIdentityBudget()
                source_path = plugin_identity._module_file_source_path(
                    module,
                    budget=budget,
                )
                self.assertIsNotNone(source_path)
                assert source_path is not None
                with patch.object(
                    plugin_identity,
                    "_loaded_global_dependencies",
                    wraps=plugin_identity._loaded_global_dependencies,
                ) as loaded_dependencies:
                    plugin_identity._external_function_leaf_identity(
                        module.callback,
                        module=module,
                        module_name=module_name,
                        qualified_name="callback",
                        source_path=source_path,
                        budget=budget,
                        scope_cache={},
                        callable_cache={},
                        active_callables=set(),
                        identity_root=module_name,
                        depth=0,
                    )
                self.assertEqual(loaded_dependencies.call_count, 1)
                self.assertEqual(len(budget.function_dependency_analyses), 1)

                original_code = module.callback.__code__
                module.callback.__code__ = module.replacement.__code__
                try:
                    with self.assertRaisesRegex(
                        PluginExecutableIdentityError,
                        "function code changed while fingerprinting",
                    ):
                        plugin_identity._function_dependency_analysis(
                            module.callback,
                            budget=budget,
                            depth=0,
                        )
                finally:
                    module.callback.__code__ = original_code
            finally:
                self._cleanup_modules(temporary, module_name)

    def test_mapping_cardinality_is_reserved_before_sorting(self) -> None:
        mapping = {f"name_{index:04d}": None for index in range(1_000)}
        function = cast(
            FunctionType,
            type(self).test_mapping_cardinality_is_reserved_before_sorting,
        )
        module = sys.modules[__name__]
        operations = {
            "runtime": lambda: plugin_identity._update_runtime_mapping(
                hashlib.sha256(),
                mapping,
                budget=plugin_identity._TargetIdentityBudget(),
                scope_cache={},
                callable_cache={},
                active_callables=set(),
                identity_root=__name__,
                depth=0,
                label="runtime mapping",
            ),
            "external": lambda: plugin_identity._update_external_runtime_mapping(
                hashlib.sha256(),
                mapping,
                function=function,
                module=module,
                budget=plugin_identity._TargetIdentityBudget(),
                scope_cache={},
                callable_cache={},
                active_callables=set(),
                identity_root=__name__,
                depth=0,
                label="external mapping",
            ),
            "annotations": lambda: plugin_identity._update_annotation_shape(
                hashlib.sha256(),
                mapping,
                budget=plugin_identity._TargetIdentityBudget(),
            ),
        }
        for label, operation in operations.items():
            with (
                self.subTest(path=label),
                patch.object(plugin_identity, "_MAX_TARGET_VALUE_NODES", 999),
                patch.object(
                    plugin_identity,
                    "sorted",
                    side_effect=AssertionError("sorted before cardinality bound"),
                    create=True,
                ),
                self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "recursive value limit",
                ),
            ):
                operation()

    def test_runtime_import_source_is_bounded_before_ast_allocation(self) -> None:
        source = "\n".join(
            f"def function_{index}():\n    return {index}"
            for index in range(100)
        )
        with tempfile.TemporaryDirectory() as temporary:
            source_path = Path(temporary) / "oversized_imports.py"
            source_path.write_text(source, encoding="utf-8")
            with (
                patch.object(plugin_identity, "_MAX_TARGET_VALUE_NODES", 64),
                patch.object(
                    plugin_identity.ast,
                    "parse",
                    wraps=ast.parse,
                ) as parse,
                self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "recursive value limit",
                ),
            ):
                plugin_identity._declared_function_ast(
                    module_name="oversized_imports",
                    qualified_name="function_0",
                    source_path=source_path,
                    budget=plugin_identity._TargetIdentityBudget(),
                )
            self.assertEqual(parse.call_count, 0)

    def test_runtime_import_ast_is_bounded_before_function_collection(self) -> None:
        oversized_tree = ast.Module(
            body=[
                ast.FunctionDef(
                    name=f"function_{index}",
                    args=ast.arguments(
                        posonlyargs=[],
                        args=[],
                        kwonlyargs=[],
                        kw_defaults=[],
                        defaults=[],
                    ),
                    body=[ast.Pass()],
                    decorator_list=[],
                )
                for index in range(100)
            ],
            type_ignores=[],
        )
        with tempfile.TemporaryDirectory() as temporary:
            source_path = Path(temporary) / "small_imports.py"
            source_path.write_text("def selected():\n    pass\n", encoding="utf-8")
            with (
                patch.object(plugin_identity, "_MAX_TARGET_VALUE_NODES", 64),
                patch.object(plugin_identity.ast, "parse", return_value=oversized_tree),
                patch.object(
                    plugin_identity,
                    "_qualified_function_nodes",
                    side_effect=AssertionError(
                        "function nodes collected before AST node bound"
                    ),
                ),
                self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "recursive value limit",
                ),
            ):
                plugin_identity._declared_function_ast(
                    module_name="small_imports",
                    qualified_name="selected",
                    source_path=source_path,
                    budget=plugin_identity._TargetIdentityBudget(),
                )

    def test_native_module_subclass_is_rejected_before_namespace_access(
        self,
    ) -> None:
        class HostileNativeModule(ModuleType):
            def __getattribute__(self, name: str) -> object:
                if name in {"__dict__", "__name__", "__spec__"}:
                    raise AssertionError("hostile module namespace was accessed")
                return super().__getattribute__(name)

        module = HostileNativeModule("hostile_native")
        with self.assertRaisesRegex(
            PluginExecutableIdentityError,
            "no exact loaded provenance",
        ):
            plugin_identity._build_native_export_index(
                module,
                budget=plugin_identity._TargetIdentityBudget(),
                depth=0,
            )

    def test_instance_state_cardinality_is_reserved_before_sorting(self) -> None:
        module_name = "_rda_identity_bounded_instance_state"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "class Configuration:\n"
                    "    def __call__(self, value):\n"
                    "        return value\n\n"
                    "oversized = Configuration()\n"
                    "for index in range(192):\n"
                    "    setattr(oversized, f'state_{index:04d}', None)\n"
                )
            },
            module_name,
        )

        def identity(budget: plugin_identity._TargetIdentityBudget) -> str:
            return plugin_identity._instance_runtime_identity(
                module.oversized,
                budget=budget,
                scope_cache={},
                callable_cache={},
                active_callables=set(),
                identity_root=module_name,
                depth=0,
            )

        try:
            expected_count = len(module.oversized.__dict__)
            original_consume = plugin_identity._consume_target_nodes
            cardinality_charges: list[tuple[int, int]] = []

            def observe_cardinality(
                budget: plugin_identity._TargetIdentityBudget,
                *,
                count: int,
                depth: int,
            ) -> None:
                if count == expected_count:
                    cardinality_charges.append((budget.value_nodes, count))
                original_consume(budget, count=count, depth=depth)

            with patch.object(
                plugin_identity,
                "_consume_target_nodes",
                side_effect=observe_cardinality,
            ):
                first = identity(plugin_identity._TargetIdentityBudget())
            second = identity(plugin_identity._TargetIdentityBudget())
            self.assertEqual(first, second)
            self.assertEqual(len(cardinality_charges), 1)
            before_charge, captured_count = cardinality_charges[0]
            self.assertEqual(captured_count, expected_count)

            actual_sorted = sorted
            state_sort_calls = 0

            def reject_state_sort(values: object, *args: object, **kwargs: object):
                nonlocal state_sort_calls
                snapshot = tuple(values)  # type: ignore[arg-type]
                if any(
                    type(item) is tuple
                    and len(item) == 2
                    and item[0] == "state_0000"
                    for item in snapshot
                ):
                    state_sort_calls += 1
                    raise AssertionError("instance state sorted before node bound")
                return actual_sorted(snapshot, *args, **kwargs)  # type: ignore[arg-type]

            with (
                patch.object(
                    plugin_identity,
                    "_MAX_TARGET_VALUE_NODES",
                    before_charge + captured_count - 1,
                ),
                patch.object(
                    plugin_identity,
                    "sorted",
                    new=reject_state_sort,
                    create=True,
                ),
                self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "recursive value limit",
                ),
            ):
                identity(plugin_identity._TargetIdentityBudget())
            self.assertEqual(state_sort_calls, 0)
        finally:
            self._cleanup_modules(temporary, module_name)

    def test_lru_state_cardinality_is_reserved_before_sorting(self) -> None:
        module_name = "_rda_identity_bounded_lru_state"
        temporary, (module,) = self._import_modules(
            {
                module_name: (
                    "from functools import lru_cache\n\n"
                    "@lru_cache(maxsize=8, typed=True)\n"
                    "def cached(value):\n"
                    "    return value\n\n"
                    "for index in range(192):\n"
                    "    setattr(cached, f'state_{index:04d}', None)\n"
                )
            },
            module_name,
        )

        def identity(budget: plugin_identity._TargetIdentityBudget) -> str:
            digest = hashlib.sha256()
            plugin_identity._update_lru_cache_wrapper_reference(
                digest,
                module.cached,
                budget=budget,
                scope_cache={},
                callable_cache={},
                active_callables=set(),
                identity_root=module_name,
                depth=0,
            )
            return digest.hexdigest()

        try:
            expected_count = len(module.cached.__dict__)
            original_consume = plugin_identity._consume_target_nodes
            cardinality_charges: list[tuple[int, int]] = []

            def observe_cardinality(
                budget: plugin_identity._TargetIdentityBudget,
                *,
                count: int,
                depth: int,
            ) -> None:
                if count == expected_count:
                    cardinality_charges.append((budget.value_nodes, count))
                original_consume(budget, count=count, depth=depth)

            with patch.object(
                plugin_identity,
                "_consume_target_nodes",
                side_effect=observe_cardinality,
            ):
                first = identity(plugin_identity._TargetIdentityBudget())
            second = identity(plugin_identity._TargetIdentityBudget())
            self.assertEqual(first, second)
            self.assertEqual(len(cardinality_charges), 1)
            before_charge, captured_count = cardinality_charges[0]
            self.assertEqual(captured_count, expected_count)

            actual_sorted = sorted
            state_sort_calls = 0

            def reject_state_sort(values: object, *args: object, **kwargs: object):
                nonlocal state_sort_calls
                snapshot = tuple(values)  # type: ignore[arg-type]
                if any(
                    type(item) is tuple
                    and len(item) == 2
                    and item[0] == "state_0000"
                    for item in snapshot
                ):
                    state_sort_calls += 1
                    raise AssertionError("LRU state sorted before node bound")
                return actual_sorted(snapshot, *args, **kwargs)  # type: ignore[arg-type]

            with (
                patch.object(
                    plugin_identity,
                    "_MAX_TARGET_VALUE_NODES",
                    before_charge + captured_count - 1,
                ),
                patch.object(
                    plugin_identity,
                    "sorted",
                    new=reject_state_sort,
                    create=True,
                ),
                self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "recursive value limit",
                ),
            ):
                identity(plugin_identity._TargetIdentityBudget())
            self.assertEqual(state_sort_calls, 0)
        finally:
            self._cleanup_modules(temporary, module_name)

    def test_native_exports_are_indexed_once_and_bounded_before_sorting(
        self,
    ) -> None:
        module_name = "_rda_identity_fake_native_exports"
        module = ModuleType(module_name)
        module.__spec__ = importlib.machinery.ModuleSpec(
            module_name,
            loader=None,
            origin="built-in",
        )
        for index in range(96):
            setattr(module, f"export_{index:04d}", object())
        sys.modules[module_name] = module
        try:
            namespace = vars(module)
            candidates = tuple(namespace.values())
            budget = plugin_identity._TargetIdentityBudget()
            with patch.object(
                plugin_identity,
                "_build_native_export_index",
                wraps=plugin_identity._build_native_export_index,
            ) as build_index:
                for _iteration in range(8):
                    for candidate in candidates:
                        plugin_identity._native_export_names(
                            module,
                            candidate,
                            budget=budget,
                            depth=0,
                        )
            self.assertEqual(build_index.call_count, 1)

            with (
                patch.object(
                    plugin_identity,
                    "_MAX_TARGET_VALUE_NODES",
                    len(namespace) - 1,
                ),
                patch.object(
                    plugin_identity,
                    "sorted",
                    side_effect=AssertionError("sorted before node bound"),
                    create=True,
                ),
                self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "recursive value limit",
                ),
            ):
                plugin_identity._native_export_names(
                    module,
                    candidates[0],
                    budget=plugin_identity._TargetIdentityBudget(),
                    depth=0,
                )

            namespace_name_bytes = sum(
                len(name.encode("utf-8")) for name in namespace
            )
            with (
                patch.object(
                    plugin_identity,
                    "_MAX_TARGET_VALUE_BYTES",
                    namespace_name_bytes - 1,
                ),
                patch.object(
                    plugin_identity,
                    "sorted",
                    side_effect=AssertionError("sorted before byte bound"),
                    create=True,
                ),
                self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "recursive runtime-byte limit",
                ),
            ):
                plugin_identity._native_export_names(
                    module,
                    candidates[0],
                    budget=plugin_identity._TargetIdentityBudget(),
                    depth=0,
                )

            actual_sorted = sorted
            mutated = False

            def mutate_during_sort(values: object) -> list[object]:
                nonlocal mutated
                if not mutated:
                    mutated = True
                    module.changed_during_index = object()
                return actual_sorted(values)  # type: ignore[arg-type, return-value]

            with (
                patch.object(
                    plugin_identity,
                    "sorted",
                    side_effect=mutate_during_sort,
                    create=True,
                ),
                self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "changed while fingerprinting",
                ),
            ):
                plugin_identity._native_export_names(
                    module,
                    candidates[0],
                    budget=plugin_identity._TargetIdentityBudget(),
                    depth=0,
                )
        finally:
            sys.modules.pop(module_name, None)

    def test_native_export_growth_during_cardinality_charge_fails_closed(
        self,
    ) -> None:
        module_name = "_rda_identity_native_charge_growth"
        module = ModuleType(module_name)
        module.__spec__ = importlib.machinery.ModuleSpec(
            module_name,
            loader=None,
            origin="built-in",
        )
        module.export = object()
        sys.modules[module_name] = module
        original_consume = plugin_identity._consume_target_nodes
        captured_size = len(vars(module))
        charged: list[int] = []
        mutated = False

        def grow_during_charge(
            budget: plugin_identity._TargetIdentityBudget,
            *,
            count: int,
            depth: int,
        ) -> None:
            nonlocal mutated
            charged.append(count)
            if not mutated:
                mutated = True
                module.grown_during_charge = object()
            original_consume(budget, count=count, depth=depth)

        try:
            with (
                patch.object(
                    plugin_identity,
                    "_consume_target_nodes",
                    side_effect=grow_during_charge,
                ),
                self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "changed while fingerprinting",
                ),
            ):
                plugin_identity._native_export_names(
                    module,
                    module.export,
                    budget=plugin_identity._TargetIdentityBudget(),
                    depth=0,
                )
            self.assertEqual(charged, [captured_size])
        finally:
            sys.modules.pop(module_name, None)

    def test_retained_token_registry_is_concurrent_and_exact(self) -> None:
        class Capability:
            pass

        with self._isolated_retained_token_registries():
            value = Capability()
            barrier = threading.Barrier(17)

            def fingerprint() -> str:
                barrier.wait(timeout=5)
                return self._retained_token_identity(value)

            with ThreadPoolExecutor(max_workers=16) as executor:
                futures = tuple(executor.submit(fingerprint) for _index in range(16))
                barrier.wait(timeout=5)
                results = [future.result(timeout=5) for future in futures]
            self.assertEqual(len(results), 16)
            self.assertEqual(len(set(results)), 1)
            self.assertEqual(
                len(plugin_identity._RETAINED_CAPABILITY_WEAK_TOKENS),
                1,
            )

    def test_retained_token_stale_callback_preserves_reused_entry(self) -> None:
        class Capability:
            pass

        with self._isolated_retained_token_registries():
            original = Capability()
            self._retained_token_identity(original)
            object_key = id(original)
            with plugin_identity._RETAINED_CAPABILITY_TOKEN_LOCK:
                original_reference, _token = (
                    plugin_identity._RETAINED_CAPABILITY_WEAK_TOKENS[object_key]
                )
                replacement = Capability()
                replacement_reference = weakref.ref(replacement)
                replacement_token = os.urandom(32)
                plugin_identity._RETAINED_CAPABILITY_WEAK_TOKENS[object_key] = (
                    replacement_reference,
                    replacement_token,
                )
            plugin_identity._retire_retained_capability_reference(
                object_key,
                original_reference,
            )
            self.assertIs(
                plugin_identity._RETAINED_CAPABILITY_WEAK_TOKENS[object_key][0],
                replacement_reference,
            )

    def test_retained_token_registries_fail_closed_at_capacity(self) -> None:
        class Capability:
            pass

        with self._isolated_retained_token_registries():
            weak_values = (Capability(), Capability())
            with patch.object(
                plugin_identity,
                "_MAX_RETAINED_CAPABILITY_WEAK_ENTRIES",
                1,
            ):
                self._retained_token_identity(weak_values[0])
                with self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "weak registry limit",
                ):
                    self._retained_token_identity(weak_values[1])
            plugin_identity._RETAINED_CAPABILITY_WEAK_TOKENS.clear()
            strong_values = (object(), object())
            with patch.object(
                plugin_identity,
                "_MAX_RETAINED_CAPABILITY_STRONG_ENTRIES",
                1,
            ):
                self._retained_token_identity(strong_values[0])
                with self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "strong registry limit",
                ):
                    self._retained_token_identity(strong_values[1])

    def test_dataclass_contract_bounds_all_fields_names_and_metadata(self) -> None:
        many_fields = dataclasses.make_dataclass(
            "ManyFields",
            [
                (
                    f"field_{index:04d}",
                    str,
                    dataclasses.field(
                        default="value",
                        metadata={"label": f"value-{index}"},
                    ),
                )
                for index in range(96)
            ],
            frozen=True,
        )
        long_name = dataclasses.make_dataclass(
            "LongName",
            [("field_" + "x" * 4_096, str, dataclasses.field(default=""))],
            frozen=True,
        )
        many_metadata = dataclasses.make_dataclass(
            "ManyMetadata",
            [
                (
                    "value",
                    str,
                    dataclasses.field(
                        default="",
                        metadata={
                            f"label-{index}": f"value-{index}"
                            for index in range(96)
                        },
                    ),
                )
            ],
            frozen=True,
        )
        long_metadata = dataclasses.make_dataclass(
            "LongMetadata",
            [
                (
                    "value",
                    str,
                    dataclasses.field(
                        default="",
                        metadata={
                            "first": "x" * 800,
                            "second": "y" * 800,
                        },
                    ),
                )
            ],
            frozen=True,
        )
        self._dataclass_contract_identity(many_fields)
        self._dataclass_contract_identity(many_metadata)
        self._dataclass_contract_identity(long_name)
        self._dataclass_contract_identity(long_metadata)
        for implementation in (many_fields, many_metadata):
            with (
                self.subTest(implementation=implementation.__name__),
                patch.object(plugin_identity, "_MAX_TARGET_VALUE_NODES", 64),
                self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "recursive value limit",
                ),
            ):
                self._dataclass_contract_identity(implementation)
        for implementation in (long_name, long_metadata):
            with (
                self.subTest(implementation=implementation.__name__),
                patch.object(plugin_identity, "_MAX_TARGET_VALUE_BYTES", 1_024),
                self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "recursive runtime-byte limit",
                ),
            ):
                self._dataclass_contract_identity(implementation)

    def test_dataclass_contract_binds_canonical_field_metadata(self) -> None:
        metadata = {"label": "primary"}
        implementation = dataclasses.make_dataclass(
            "MetadataConfiguration",
            [
                (
                    "value",
                    str,
                    dataclasses.field(default="", metadata=metadata),
                )
            ],
            frozen=True,
        )
        first = self._dataclass_contract_identity(implementation)
        metadata["label"] = "alternate"
        second = self._dataclass_contract_identity(implementation)
        self.assertNotEqual(first, second)

    def test_external_class_leaf_bounds_all_members_before_sorting(self) -> None:
        helper_name = "_rda_identity_bounded_external_class"
        callback_name = "_rda_identity_bounded_external_class_callback"
        temporary, (_helper, callback_module) = self._import_modules(
            {
                helper_name: (
                    "def apply(self, value):\n"
                    "    return value\n\n"
                    "Dependency = type(\n"
                    "    'Dependency',\n"
                    "    (),\n"
                    "    {\n"
                    "        '__module__': __name__,\n"
                    "        '__slots__': tuple(\n"
                    "            f'slot_{index:04d}_' + 'x' * 64\n"
                    "            for index in range(256)\n"
                    "        ),\n"
                    "        'apply': apply,\n"
                    "    },\n"
                    ")\n"
                    "dependency = Dependency()\n"
                ),
                callback_name: (
                    f"from {helper_name} import dependency\n\n"
                    "def callback(value):\n"
                    "    return dependency.apply(value)\n"
                ),
            },
            helper_name,
            callback_name,
        )
        try:
            executable_callable_fingerprint(callback_module.callback)
            limits = (
                ("_MAX_TARGET_VALUE_NODES", 64, "recursive value limit"),
                (
                    "_MAX_TARGET_VALUE_BYTES",
                    1_024,
                    "recursive runtime-byte limit",
                ),
            )
            for constant, limit, message in limits:
                with (
                    self.subTest(constant=constant),
                    patch.object(plugin_identity, constant, limit),
                    self.assertRaisesRegex(
                        PluginExecutableIdentityError,
                        message,
                    ),
                ):
                    executable_callable_fingerprint(callback_module.callback)
        finally:
            self._cleanup_modules(temporary, helper_name, callback_name)


if __name__ == "__main__":
    unittest.main()

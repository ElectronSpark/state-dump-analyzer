from .plugin_api import PropertyDescriptor, PropertyPatch

__all__ = ['validate_property_patch']

def validate_property_patch(patch: PropertyPatch, descriptors: tuple[PropertyDescriptor, ...]) -> None: ...

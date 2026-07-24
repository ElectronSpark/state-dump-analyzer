# Repository agent instructions

## Plug-in author documentation stewardship

This section applies only to OpenAI Codex and Fable. Other automated
agents must not perform this automatic maintenance or modify the maintained
plug-in authoring materials unless the user explicitly asks them to do so.

The maintained authoring set is:

- `docs/plugin-author-quickstart.md`
- `docs/plugin-contract.md`
- the minimal runnable plug-in example and its README
- the plug-in-authoring links and commands in `README.md`

`docs/api-contract.md` and `docs/architecture.md` join this set whenever a
change affects their public plug-in boundary.

At the end of every repository modification, before handoff, Codex or Fable
must perform a plug-in-documentation drift check:

1. Review the task-owned changes for effects on plug-in discovery, manifests,
   capabilities, input selection, parsing, source records, resource identity,
   events, reducers, relationships, dashboards, topology, routes, validation,
   errors, examples, or author-facing commands.
2. If author-visible behavior changed, update the quickstart, normative
   contract, runnable example, and relevant links in the same change.
3. Keep the quickstart linear and copy-paste runnable. Do not document an API
   path that is not exercised by the example or conformance tests.
4. Run the documented smoke/conformance commands after updating the materials.
5. If behavior did not change, do not create documentation churn; report that
   the drift check was completed and no update was required.

Documentation maintenance is part of completion and must not be deferred to a
later task.

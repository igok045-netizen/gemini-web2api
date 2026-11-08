# Experimental OpenCode retry guard

This optional OpenCode 2 server plugin stops automatic retries only when the
configured provider reports `gemini_outcome_unknown`. That marker means the
upstream may have received a generation but its outcome is unknown; the request
may still complete. It also stops automatic retries for the explicit
`gemini_model_downgraded` marker when Google reports a different model. Other
providers and errors retain their normal retry policy.

The plugin is disabled until its directory is listed in OpenCode `plugins` and
its `options.providers` contains the exact provider identifier. An empty or
missing list changes no retry behavior. Use an absolute local directory path:

```json
{
  "plugins": [{
    "package": "/absolute/path/opencode-gemini-retry-guard",
    "options": {"providers": ["gemini-local"]}
  }]
}
```

The matching server version must emit `gemini_outcome_unknown`; older server
versions do not. This guard does not make upstream generation succeed, stop
already running requests, or prevent a user from explicitly submitting again.
It has only been tested locally with synthetic failures in OpenCode 2.2.6.
Install and configure it separately if your OpenCode setup needs this guard.

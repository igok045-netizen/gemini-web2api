// Optional OpenCode 2 plugin. Register provider IDs explicitly in plugin
// options. Unknown outcomes must not be retried automatically: the original
// Gemini request may still be running. Other errors retain OpenCode's policy.
export default {
  id: "gemini-outcome-retry-guard",
  async setup(ctx) {
    const configured = ctx.options?.providers
    const allowed = new Set(Array.isArray(configured) ? configured : [])
    await ctx.session.hook("retry", (event) => {
      if (!allowed.has(event.model?.providerID)) return
      if (typeof event.error?.message !== "string") return
      if (!event.error.message.includes("gemini_outcome_unknown:") &&
          !event.error.message.includes("gemini_model_downgraded:")) return
      event.decision = { retry: false }
    })
  },
}

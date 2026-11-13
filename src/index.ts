import { Plugin } from "@opencode/plugin"
import { resolveConfig } from "./config.ts"
import { registerGuard } from "./guard.ts"

export default Plugin.define({
  id: "guard",
  setup(ctx) {
    const cfg = resolveConfig(ctx.options)
    return registerGuard(ctx, cfg)
  },
})

package app

import "os"

// Choose the route once before any request, including preflight validation.
func selectExperimentalBinaryRoute(mc ModelConfig, pending []pendingUpload, promptBytes int) (binary, legacyFallback bool, budget int) {
	config := rtCfg()
	binary, budget = config.WebChannelBinary, config.MaxPromptBytes
	imagesOnly := true
	for _, upload := range pending {
		imagesOnly = imagesOnly && upload.Kind == 1
	}
	legacyFallback = useExperimentalLegacyFallback(binary, firefoxChannelCookiePath() != "", len(pending), imagesOnly, mc.Tool, mc.Cont != nil, promptBytes, budget)
	if legacyFallback {
		binary = false
	}
	return binary, legacyFallback, budget
}

// Select before making any upstream generation request. This opt-in route
// preserves unsupported input by using the existing legacy implementation;
// it never retries a request that was already sent using another transport.
func useExperimentalLegacyFallback(binary, browserSession bool, pending int, imagesOnly bool, tool int, continuation bool, promptBytes, budget int) bool {
	if !binary || !browserSession {
		return false
	}
	switch os.Getenv("GEMINI_EXPERIMENTAL_LEGACY_FALLBACK") {
	case "images":
		return pending > 0 && imagesOnly && tool == 0 && !continuation && (budget <= 0 || promptBytes <= budget)
	case "1":
		return pending > 0 || tool > 0 || continuation || (budget > 0 && promptBytes > budget)
	default:
		return false
	}
}

package management

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// GetRoutingQuotaStatus reports how the soonest-quota-reset strategy sees each
// credential and the most recent selection decisions. The response identifies
// credentials only by auth index and never includes tokens, emails, or request content.
func (h *Handler) GetRoutingQuotaStatus(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth manager unavailable"})
		return
	}
	provider := strings.TrimSpace(c.Query("provider"))
	model := strings.TrimSpace(c.Query("model"))
	c.JSON(http.StatusOK, h.authManager.QuotaRoutingReport(provider, model))
}

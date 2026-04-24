package handler

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
)

func GetRequestCountryUpdateStatus(c *gin.Context) {
	c.JSON(http.StatusOK, buildRequestCountryUpdateStatus())
}

func UploadRequestCountryUpdateConfig(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "multipart form field 'file' is required"})
		return
	}
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	defer src.Close()
	if err := writeManagedRequestCountryGeoIPConfig(src); err != nil {
		if respondIfConfigDBStoreRequired(c, err) {
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, buildRequestCountryUpdateStatus())
}

func DeleteRequestCountryUpdateConfig(c *gin.Context) {
	if err := removeManagedRequestCountryGeoIPConfig(); err != nil {
		if respondIfConfigDBStoreRequired(c, err) {
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, buildRequestCountryUpdateStatus())
}

func RunRequestCountryUpdateNow(c *gin.Context) {
	if err := requestCountryUpdateNowFunc(context.Background()); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error":  err.Error(),
			"status": buildRequestCountryUpdateStatus(),
		})
		return
	}
	c.JSON(http.StatusOK, buildRequestCountryUpdateStatus())
}

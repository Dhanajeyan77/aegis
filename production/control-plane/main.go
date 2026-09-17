package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Event struct {
	PID     uint32 `json:"pid"`
	Command string `json:"comm"`
	Target  string `json:"target"`
	Blocked bool   `json:"blocked"`
}

var events []Event

func main() {
	r := gin.Default()

	// API for Rust Agents to send events
	r.POST("/api/v1/events", func(c *gin.Context) {
		var event Event
		if err := c.ShouldBindJSON(&event); err == nil {
			events = append(events, event)
			log.Printf("Received Event: %+v\\n", event)
			c.JSON(http.StatusOK, gin.H{"status": "recorded"})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
	})

	// API for the Web UI Dashboard
	r.GET("/api/v1/events", func(c *gin.Context) {
		c.JSON(http.StatusOK, events)
	})

	log.Println("Aegis-BPF Go Control Plane running on :8080")
	r.Run(":8080")
}

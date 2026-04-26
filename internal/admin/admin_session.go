package admin

import (
	"fmt"
	"password-manager/internal/audit"
	"password-manager/internal/models"
	"sync"
	"time"
)

// SessionManager manages user sessions
// Requirement 3.6: The tool shall implement session management controls
type SessionManager struct {
	mu             sync.RWMutex
	sessions       map[string]*models.Session
	maxIdleTime    time.Duration // Maximum idle time before session timeout
	maxSessionTime time.Duration // Maximum total session duration
	logger         *audit.AuditLogger
}

// NewSessionManager creates a session manager with default timeouts
func NewSessionManager(logger *audit.AuditLogger) *SessionManager {
	return &SessionManager{
		sessions:       make(map[string]*models.Session),
		maxIdleTime:    15 * time.Minute, // 15 minute idle timeout
		maxSessionTime: 8 * time.Hour,    // 8 hour max session
		logger:         logger,
	}
}

// SetIdleTimeout sets the maximum idle timeout
func (sm *SessionManager) SetIdleTimeout(d time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.maxIdleTime = d
}

// SetMaxSessionTime sets the maximum session duration
func (sm *SessionManager) SetMaxSessionTime(d time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.maxSessionTime = d
}

// CreateSession creates a new session for a user
func (sm *SessionManager) CreateSession(username, token string) *models.Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	session := &models.Session{
		ID:           fmt.Sprintf("session_%d", now.UnixNano()),
		Username:     username,
		Token:        token,
		CreatedAt:    now,
		ExpiresAt:    now.Add(sm.maxSessionTime),
		LastActivity: now,
		IsActive:     true,
	}

	sm.sessions[session.ID] = session

	if sm.logger != nil {
		sm.logger.Log(username, audit.ActionLogin, "session", fmt.Sprintf("session_id=%s", session.ID), "success")
	}

	return session
}

// ValidateSession checks if a session is valid and not expired
func (sm *SessionManager) ValidateSession(sessionID string) (*models.Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	if !session.IsActive {
		return nil, fmt.Errorf("session is inactive")
	}

	now := time.Now()

	// Check max session time
	if now.After(session.ExpiresAt) {
		session.IsActive = false
		return nil, fmt.Errorf("session expired")
	}

	// Check idle timeout
	if now.Sub(session.LastActivity) > sm.maxIdleTime {
		session.IsActive = false
		if sm.logger != nil {
			sm.logger.Log(session.Username, audit.ActionSessionTimeout, "session",
				fmt.Sprintf("session_id=%s, idle_timeout", sessionID), "timeout")
		}
		return nil, fmt.Errorf("session timed out due to inactivity")
	}

	// Update last activity
	session.LastActivity = now
	return session, nil
}

// InvalidateSession terminates a session
func (sm *SessionManager) InvalidateSession(sessionID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found")
	}

	session.IsActive = false

	if sm.logger != nil {
		sm.logger.Log(session.Username, audit.ActionLogout, "session",
			fmt.Sprintf("session_id=%s", sessionID), "success")
	}

	return nil
}

// InvalidateAllUserSessions terminates all sessions for a user
func (sm *SessionManager) InvalidateAllUserSessions(username string) int {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	count := 0
	for _, session := range sm.sessions {
		if session.Username == username && session.IsActive {
			session.IsActive = false
			count++
		}
	}

	if sm.logger != nil && count > 0 {
		sm.logger.Log(username, audit.ActionLogout, "session",
			fmt.Sprintf("all sessions invalidated, count=%d", count), "success")
	}

	return count
}

// GetActiveSessions returns all active sessions
func (sm *SessionManager) GetActiveSessions() []*models.Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var active []*models.Session
	now := time.Now()
	for _, session := range sm.sessions {
		if session.IsActive && now.Before(session.ExpiresAt) {
			active = append(active, session)
		}
	}
	return active
}

// GetUserSessions returns active sessions for a specific user
func (sm *SessionManager) GetUserSessions(username string) []*models.Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var userSessions []*models.Session
	for _, session := range sm.sessions {
		if session.Username == username && session.IsActive {
			userSessions = append(userSessions, session)
		}
	}
	return userSessions
}

// CleanupExpiredSessions removes expired sessions
func (sm *SessionManager) CleanupExpiredSessions() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	count := 0
	for id, session := range sm.sessions {
		if now.After(session.ExpiresAt) || !session.IsActive {
			delete(sm.sessions, id)
			count++
		}
	}
	return count
}

package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "crypto/rand"
    "github.com/hunter-420/opaque-pake/internal/opaque"
)

type RegisterRequest struct {
    Blinded []byte `json:"blinded"`
}

type RegisterResponse struct {
    Evaluated []byte `json:"evaluated"`
}

type RegisterFinalRequest struct {
    Envelope opaque.EnvelopeData `json:"envelope"`
}

type LoginRequest struct {
    Blinded           []byte `json:"blinded"`
    ClientPkStatic    []byte `json:"client_pk_static"`
    ClientPkEphemeral []byte `json:"client_pk_ephemeral"`
    ClientIdentity    []byte `json:"client_identity"`
}

type LoginResponse struct {
    Evaluated         []byte              `json:"evaluated"`
    ServerPkStatic    []byte              `json:"server_pk_static"`
    ServerPkEphemeral []byte              `json:"server_pk_ephemeral"`
    Envelope          opaque.EnvelopeData `json:"envelope"`
}

func main() {
    curve := opaque.RistrettoCurve{} // Switch to opaque.P256Curve{} for NIST P-256
    op := opaque.NewOpaque(curve, rand.Reader)
    store := make(map[string]opaque.EnvelopeData) // Simple in-memory store

    http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
        var req RegisterRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }
        evaluated, err := op.OprfEvaluate(curve.PointToBytes(req.Blinded))
        if err != nil {
            http.Error(w, "Evaluation failed", http.StatusBadRequest)
            return
        }
        resp := RegisterResponse{Evaluated: curve.PointToBytes(evaluated)}
        json.NewEncoder(w).Encode(resp)
    })

    http.HandleFunc("/register-final", func(w http.ResponseWriter, r *http.Request) {
        var req RegisterFinalRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }
        store[string(req.Envelope.ClientIdentity)] = req.Envelope
        fmt.Fprintf(w, "Registration successful")
    })

    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        var req LoginRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }
        envelope, exists := store[string(req.ClientIdentity)]
        if !exists {
            http.Error(w, "User not found", http.StatusNotFound)
            return
        }
        evaluated, err := op.OprfEvaluate(curve.PointToBytes(req.Blinded))
        if err != nil {
            http.Error(w, "Evaluation failed", http.StatusBadRequest)
            return
        }
        _, serverPkEphemeral, sessionKey, err := op.AkeServerRespond(curve.PointToBytes(req.ClientPkStatic), curve.PointToBytes(req.ClientPkEphemeral), op.serverPkStatic, rand.Reader)
        if err != nil {
            http.Error(w, "AKE failed", http.StatusBadRequest)
            return
        }
        resp := LoginResponse{
            Evaluated:         curve.PointToBytes(evaluated),
            ServerPkStatic:    curve.PointToBytes(op.serverPkStatic),
            ServerPkEphemeral: curve.PointToBytes(serverPkEphemeral),
            Envelope:          envelope,
        }
        fmt.Printf("Server session key: %x\n", sessionKey)
        json.NewEncoder(w).Encode(resp)
    })

    fmt.Println("Server running on :8080")
    http.ListenAndServe(":8080", nil)
}

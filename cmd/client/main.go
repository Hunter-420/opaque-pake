package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "crypto/rand"
    "github.com/yourusername/opaque-pake/internal/opaque"
)

func main() {
    curve := opaque.RistrettoCurve{} // Switch to opaque.P256Curve{} for NIST P-256
    op := opaque.NewOpaque(curve, rand.Reader)
    password := []byte("password123")
    clientIdentity := []byte("user@example.com")

    // Registration
    r, blinded, err := op.OprfBlind(password, rand.Reader)
    if err != nil {
        fmt.Println("Blind failed:", err)
        return
    }
    reqBody, _ := json.Marshal(opaque.RegisterRequest{Blinded: curve.PointToBytes(blinded)})
    resp, err := http.Post("http://localhost:8080/register", "application/json", bytes.NewBuffer(reqBody))
    if err != nil {
        fmt.Println("Register request failed:", err)
        return
    }
    var regResp opaque.RegisterResponse
    json.NewDecoder(resp.Body).Decode(&regResp)
    hardenedKey, err := op.OprfUnblind(r, curve.PointToBytes(regResp.Evaluated))
    if err != nil {
        fmt.Println("Unblind failed:", err)
        return
    }
    clientSkStatic, _, _, _, err := op.AkeClientInit(rand.Reader)
    if err != nil {
        fmt.Println("AKE init failed:", err)
        return
    }
    envelope, err := op.CreateEnvelope(hardenedKey, clientSkStatic, op.serverPkStatic, clientIdentity, rand.Reader)
    if err != nil {
        fmt.Println("Envelope creation failed:", err)
        return
    }
    finalReq, _ := json.Marshal(opaque.RegisterFinalRequest{Envelope: envelope})
    http.Post("http://localhost:8080/register-final", "application/json", bytes.NewBuffer(finalReq))

    // Login
    r, blinded, clientSkStatic, clientPkStatic, clientSkEphemeral, clientPkEphemeral, err := op.LoginClientInit(password, rand.Reader)
    if err != nil {
        fmt.Println("Login init failed:", err)
        return
    }
    loginReq, _ := json.Marshal(opaque.LoginRequest{
        Blinded:           curve.PointToBytes(blinded),
        ClientPkStatic:    curve.PointToBytes(clientPkStatic),
        ClientPkEphemeral: curve.PointToBytes(clientPkEphemeral),
        ClientIdentity:    clientIdentity,
    })
    resp, err = http.Post("http://localhost:8080/login", "application/json", bytes.NewBuffer(loginReq))
    if err != nil {
        fmt.Println("Login request failed:", err)
        return
    }
    var loginResp opaque.LoginResponse
    json.NewDecoder(resp.Body).Decode(&loginResp)
    _, sessionKey, exportKey, err := op.LoginClientFinalize(r, clientSkStatic, clientSkEphemeral, curve.PointToBytes(loginResp.Evaluated), curve.PointToBytes(loginResp.ServerPkStatic), curve.PointToBytes(loginResp.ServerPkEphemeral), loginResp.Envelope)
    if err != nil {
        fmt.Println("Login finalize failed:", err)
        return
    }
    fmt.Printf("Client session key: %x\n", sessionKey)
    fmt.Printf("Export key: %x\n", exportKey)
}

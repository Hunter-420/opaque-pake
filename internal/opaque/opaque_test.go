package opaque

import (
    "crypto/rand"
    "testing"
)

func BenchmarkOpaque(b *testing.B) {
    rng := rand.Reader
    password := []byte("password123")
    clientIdentity := []byte("user@example.com")

    for _, curve := range []Curve{RistrettoCurve{}, P256Curve{}} {
        op := NewOpaque(curve, rng)
        r, blinded, err := op.OprfBlind(password, rng)
        if err != nil {
            b.Fatal(err)
        }
        evaluated, err := op.OprfEvaluate(blinded)
        if err != nil {
            b.Fatal(err)
        }
        hardenedKey, err := op.OprfUnblind(r, evaluated)
        if err != nil {
            b.Fatal(err)
        }
        clientSkStatic, _, _, _, err := op.AkeClientInit(rng)
        if err != nil {
            b.Fatal(err)
        }
        envelope, err := op.CreateEnvelope(hardenedKey, clientSkStatic, op.serverPkStatic, clientIdentity, rng)
        if err != nil {
            b.Fatal(err)
        }

        b.Run("OPRF Blind "+curveName(curve), func(b *testing.B) {
            for i := 0; i < b.N; i++ {
                op.OprfBlind(password, rng)
            }
        })
        b.Run("OPRF Evaluate "+curveName(curve), func(b *testing.B) {
            for i := 0; i < b.N; i++ {
                op.OprfEvaluate(blinded)
            }
        })
        b.Run("OPRF Unblind "+curveName(curve), func(b *testing.B) {
            for i := 0; i < b.N; i++ {
                op.OprfUnblind(r, evaluated)
            }
        })
        b.Run("AKE Client Init "+curveName(curve), func(b *testing.B) {
            for i := 0; i < b.N; i++ {
                op.AkeClientInit(rng)
            }
        })
        b.Run("AKE Server Respond "+curveName(curve), func(b *testing.B) {
            _, clientPkStatic, _, clientPkEphemeral, _ := op.AkeClientInit(rng)
            for i := 0; i < b.N; i++ {
                op.AkeServerRespond(clientPkStatic, clientPkEphemeral, op.serverPkStatic, rng)
            }
        })
        b.Run("AKE Client Finalize "+curveName(curve), func(b *testing.B) {
            _, clientPkStatic, clientSkEphemeral, clientPkEphemeral, _ := op.AkeClientInit(rng)
            _, serverPkEphemeral, _, _ := op.AkeServerRespond(clientPkStatic, clientPkEphemeral, op.serverPkStatic, rng)
            for i := 0; i < b.N; i++ {
                op.AkeClientFinalize(clientSkStatic, clientSkEphemeral, op.serverPkStatic, serverPkEphemeral)
            }
        })
        b.Run("Full Login "+curveName(curve), func(b *testing.B) {
            for i := 0; i < b.N; i++ {
                r, blinded, clientSkStatic, clientPkStatic, clientSkEphemeral, clientPkEphemeral, _ := op.LoginClientInit(password, rng)
                evaluated, serverPkStatic, serverPkEphemeral, _, envelope, _ := op.LoginServerRespond(blinded, clientPkStatic, clientPkEphemeral, envelope, rng)
                op.LoginClientFinalize(r, clientSkStatic, clientSkEphemeral, evaluated, serverPkStatic, serverPkEphemeral, envelope)
            }
        })
    }
}

func curveName(curve Curve) string {
    switch curve.(type) {
    case RistrettoCurve:
        return "Ristretto255"
    case P256Curve:
        return "P256"
    default:
        return "Unknown"
    }
}

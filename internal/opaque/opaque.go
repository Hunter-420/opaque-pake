package opaque

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/sha256"
    "errors"
    "github.com/gtank/ristretto255"
    "golang.org/x/crypto/hkdf"
    "io"
    "math/big"
)

// Curve interface for curve-agnostic operations
type Curve interface {
    RandomScalar(rng io.Reader) (interface{}, error)
    ScalarMult(scalar, point interface{}) interface{}
    BasepointMult(scalar interface{}) interface{}
    HashToScalar(data []byte) interface{}
    PointToBytes(point interface{}) []byte
    ScalarToBytes(scalar interface{}) []byte
    ScalarInvert(scalar interface{}) interface{}
    ValidatePoint(point interface{}) bool
}

// RistrettoCurve implements ristretto255
type RistrettoCurve struct{}

func (RistrettoCurve) RandomScalar(rng io.Reader) (interface{}, error) {
    scalar := ristretto255.NewScalar()
    _, err := io.ReadFull(rng, scalar.Encode([]byte{}))
    if err != nil {
        return nil, err
    }
    return scalar, nil
}

func (RistrettoCurve) ScalarMult(scalar, point interface{}) interface{} {
    element := ristretto255.NewElement()
    element.ScalarMult(scalar.(*ristretto255.Scalar), point.(*ristretto255.Element))
    return element
}

func (RistrettoCurve) BasepointMult(scalar interface{}) interface{} {
    element := ristretto255.NewElement()
    element.ScalarMult(scalar.(*ristretto255.Scalar), ristretto255.NewElement().Base())
    return element
}

func (RistrettoCurve) HashToScalar(data []byte) interface{} {
    scalar := ristretto255.NewScalar()
    hash := sha256.Sum256(data)
    scalar.FromUniformBytes(hash[:])
    return scalar
}

func (RistrettoCurve) PointToBytes(point interface{}) []byte {
    return point.(*ristretto255.Element).Encode([]byte{})
}

func (RistrettoCurve) ScalarToBytes(scalar interface{}) []byte {
    return scalar.(*ristretto255.Scalar).Encode([]byte{})
}

func (RistrettoCurve) ScalarInvert(scalar interface{}) interface{} {
    inverted := ristretto255.NewScalar()
    inverted.Invert(scalar.(*ristretto255.Scalar))
    return inverted
}

func (RistrettoCurve) ValidatePoint(point interface{}) bool {
    return true // Ristretto255 handles validation internally
}

// P256Curve implements NIST P-256
type P256Curve struct{}

func (P256Curve) RandomScalar(rng io.Reader) (interface{}, error) {
    priv, err := ecdsa.GenerateKey(elliptic.P256(), rng)
    if err != nil {
        return nil, err
    }
    return priv.D, nil
}

func (P256Curve) ScalarMult(scalar, point interface{}) interface{} {
    x, y := elliptic.P256().ScalarMult(point.(*ecdsa.PublicKey).X, point.(*ecdsa.PublicKey).Y, scalar.(*big.Int).Bytes())
    return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
}

func (P256Curve) BasepointMult(scalar interface{}) interface{} {
    x, y := elliptic.P256().ScalarBaseMult(scalar.(*big.Int).Bytes())
    return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
}

func (P256Curve) HashToScalar(data []byte) interface{} {
    hash := sha256.Sum256(data)
    return new(big.Int).SetBytes(hash[:]).Mod(new(big.Int).SetBytes(hash[:]), elliptic.P256().Params().N)
}

func (P256Curve) PointToBytes(point interface{}) []byte {
    return elliptic.Marshal(elliptic.P256(), point.(*ecdsa.PublicKey).X, point.(*ecdsa.PublicKey).Y)
}

func (P256Curve) ScalarToBytes(scalar interface{}) []byte {
    return scalar.(*big.Int).Bytes()
}

func (P256Curve) ScalarInvert(scalar interface{}) interface{} {
    return new(big.Int).ModInverse(scalar.(*big.Int), elliptic.P256().Params().N)
}

func (P256Curve) ValidatePoint(point interface{}) bool {
    p := point.(*ecdsa.PublicKey)
    return p.Curve.IsOnCurve(p.X, p.Y)
}

// EnvelopeData holds encrypted credentials
type EnvelopeData struct {
    Nonce           []byte
    Ciphertext      []byte
    ServerPublicKey []byte
    ClientIdentity  []byte
}

// Opaque struct
type Opaque struct {
    Curve          Curve
    OprfKey        interface{}
    serverSkStatic interface{}
    serverPkStatic interface{}
}

// NewOpaque initializes Opaque
func NewOpaque(curve Curve, rng io.Reader) *Opaque {
    oprfKey, _ := curve.RandomScalar(rng)
    serverSkStatic, _ := curve.RandomScalar(rng)
    serverPkStatic := curve.BasepointMult(serverSkStatic)
    return &Opaque{Curve: curve, OprfKey: oprfKey, serverSkStatic: serverSkStatic, serverPkStatic: serverPkStatic}
}

// OprfBlind blinds the password
func (o *Opaque) OprfBlind(password []byte, rng io.Reader) (interface{}, interface{}, error) {
    r, err := o.Curve.RandomScalar(rng)
    if err != nil {
        return nil, nil, err
    }
    hashed := o.Curve.HashToScalar(password)
    blinded := o.Curve.BasepointMult(hashed)
    blinded = o.Curve.ScalarMult(r, blinded)
    return r, blinded, nil
}

// OprfEvaluate evaluates the blinded input
func (o *Opaque) OprfEvaluate(blinded interface{}) (interface{}, error) {
    if !o.Curve.ValidatePoint(blinded) {
        return nil, errors.New("invalid point")
    }
    return o.Curve.ScalarMult(o.OprfKey, blinded), nil
}

// OprfUnblind unblinds the evaluated result
func (o *Opaque) OprfUnblind(r, evaluated interface{}) (interface{}, error) {
    rInv := o.Curve.ScalarInvert(r)
    return o.Curve.ScalarMult(rInv, evaluated), nil
}

// AkeClientInit generates client keys
func (o *Opaque) AkeClientInit(rng io.Reader) (interface{}, interface{}, interface{}, interface{}, error) {
    clientSkStatic, err := o.Curve.RandomScalar(rng)
    if err != nil {
        return nil, nil, nil, nil, err
    }
    clientPkStatic := o.Curve.BasepointMult(clientSkStatic)
    clientSkEphemeral, err := o.Curve.RandomScalar(rng)
    if err != nil {
        return nil, nil, nil, nil, err
    }
    clientPkEphemeral := o.Curve.BasepointMult(clientSkEphemeral)
    return clientSkStatic, clientPkStatic, clientSkEphemeral, clientPkEphemeral, nil
}

// AkeServerRespond implements 3DH
func (o *Opaque) AkeServerRespond(clientPkStatic, clientPkEphemeral, serverPkStatic interface{}, rng io.Reader) (interface{}, interface{}, []byte, error) {
    if !o.Curve.ValidatePoint(clientPkStatic) || !o.Curve.ValidatePoint(clientPkEphemeral) {
        return nil, nil, nil, errors.New("invalid client public key")
    }
    // Generate ephemeral private key
    serverSkEphemeral, err := o.Curve.RandomScalar(rng)
    if err != nil {
        return nil, nil, nil, err
    }
    // Explicitly use serverSkEphemeral to satisfy compiler
    _ = o.Curve.ScalarToBytes(serverSkEphemeral) // Convert to bytes to ensure usage
    // Compute ephemeral public key
    serverPkEphemeral := o.Curve.BasepointMult(serverSkEphemeral)
    // Compute Diffie-Hellman components
    dh1 := o.Curve.ScalarMult(serverSkEphemeral, clientPkStatic)
    dh2 := o.Curve.ScalarMult(serverSkEphemeral, clientPkEphemeral)
    dh3 := o.Curve.ScalarMult(o.serverSkStatic, clientPkEphemeral)
    // Derive shared secret
    sharedSecret := append(o.Curve.PointToBytes(dh1), append(o.Curve.PointToBytes(dh2), o.Curve.PointToBytes(dh3)...)...)
    sessionKey := o.deriveSessionKey(sharedSecret)
    // Return ephemeral private key, public key, and session key
    return serverSkEphemeral, serverPkEphemeral, sessionKey, nil
}

// AkeClientFinalize implements 3DH
func (o *Opaque) AkeClientFinalize(clientSkStatic, clientSkEphemeral, serverPkStatic, serverPkEphemeral interface{}) ([]byte, error) {
    if !o.Curve.ValidatePoint(serverPkStatic) || !o.Curve.ValidatePoint(serverPkEphemeral) {
        return nil, errors.New("invalid server public key")
    }
    dh1 := o.Curve.ScalarMult(clientSkStatic, serverPkEphemeral)
    dh2 := o.Curve.ScalarMult(clientSkEphemeral, serverPkStatic)
    dh3 := o.Curve.ScalarMult(clientSkEphemeral, serverPkEphemeral)
    sharedSecret := append(o.Curve.PointToBytes(dh1), append(o.Curve.PointToBytes(dh2), o.Curve.PointToBytes(dh3)...)...)
    return o.deriveSessionKey(sharedSecret), nil
}

func (o *Opaque) deriveSessionKey(sharedSecret []byte) []byte {
    hkdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("OPAQUE session key"))
    key := make([]byte, 32)
    hkdf.Read(key)
    return key
}

// CreateEnvelope encrypts credentials
func (o *Opaque) CreateEnvelope(hardenedKey, privateKey, serverPublicKey interface{}, clientIdentity []byte, rng io.Reader) (EnvelopeData, error) {
    key := o.deriveSessionKey(o.Curve.PointToBytes(hardenedKey))
    nonce := make([]byte, 12)
    if _, err := rng.Read(nonce); err != nil {
        return EnvelopeData{}, err
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return EnvelopeData{}, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return EnvelopeData{}, err
    }
    privateKeyBytes := o.Curve.ScalarToBytes(privateKey)
    ciphertext := gcm.Seal(nil, nonce, privateKeyBytes, nil)
    return EnvelopeData{
        Nonce:           nonce,
        Ciphertext:      ciphertext,
        ServerPublicKey: o.Curve.PointToBytes(serverPublicKey),
        ClientIdentity:  clientIdentity,
    }, nil
}

// RecoverEnvelope decrypts credentials
func (o *Opaque) RecoverEnvelope(hardenedKey interface{}, envelope EnvelopeData) (interface{}, []byte, []byte, error) {
    key := o.deriveSessionKey(o.Curve.PointToBytes(hardenedKey))
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, nil, nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, nil, nil, err
    }
    privateKeyBytes, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, nil)
    if err != nil {
        return nil, nil, nil, err
    }
    return o.Curve.HashToScalar(privateKeyBytes), envelope.ServerPublicKey, envelope.ClientIdentity, nil
}

// Register handles registration
func (o *Opaque) Register(password []byte, serverPublicKey interface{}, clientIdentity []byte, rng io.Reader) (EnvelopeData, error) {
    r, blinded, err := o.OprfBlind(password, rng)
    if err != nil {
        return EnvelopeData{}, err
    }
    evaluated, err := o.OprfEvaluate(blinded)
    if err != nil {
        return EnvelopeData{}, err
    }
    hardenedKey, err := o.OprfUnblind(r, evaluated)
    if err != nil {
        return EnvelopeData{}, err
    }
    clientSkStatic, _, _, _, err := o.AkeClientInit(rng)
    if err != nil {
        return EnvelopeData{}, err
    }
    return o.CreateEnvelope(hardenedKey, clientSkStatic, serverPublicKey, clientIdentity, rng)
}

// LoginClientInit starts login
func (o *Opaque) LoginClientInit(password []byte, rng io.Reader) (interface{}, interface{}, interface{}, interface{}, interface{}, interface{}, error) {
    r, blinded, err := o.OprfBlind(password, rng)
    if err != nil {
        return nil, nil, nil, nil, nil, nil, err
    }
    clientSkStatic, clientPkStatic, clientSkEphemeral, clientPkEphemeral, err := o.AkeClientInit(rng)
    if err != nil {
        return nil, nil, nil, nil, nil, nil, err
    }
    return r, blinded, clientSkStatic, clientPkStatic, clientSkEphemeral, clientPkEphemeral, nil
}

// LoginServerRespond processes login request
func (o *Opaque) LoginServerRespond(blinded, clientPkStatic, clientPkEphemeral interface{}, envelope EnvelopeData, rng io.Reader) (interface{}, interface{}, interface{}, []byte, EnvelopeData, error) {
    evaluated, err := o.OprfEvaluate(blinded)
    if err != nil {
        return nil, nil, nil, nil, EnvelopeData{}, err
    }
    serverSkEphemeral, serverPkEphemeral, sessionKey, err := o.AkeServerRespond(clientPkStatic, clientPkEphemeral, o.serverPkStatic, rng)
    if err != nil {
        return nil, nil, nil, nil, EnvelopeData{}, err
    }
    return evaluated, o.serverPkStatic, serverPkEphemeral, sessionKey, envelope, nil
}

// LoginClientFinalize completes login
func (o *Opaque) LoginClientFinalize(r, clientSkStatic, clientSkEphemeral, evaluated, serverPkStatic, serverPkEphemeral interface{}, envelope EnvelopeData) (interface{}, []byte, []byte, error) {
    hardenedKey, err := o.OprfUnblind(r, evaluated)
    if err != nil {
        return nil, nil, nil, err
    }
    privateKey, serverPublicKey, clientIdentity, err := o.RecoverEnvelope(hardenedKey, envelope)
    if err != nil {
        return nil, nil, nil, err
    }
    sessionKey, err := o.AkeClientFinalize(clientSkStatic, clientSkEphemeral, serverPkStatic, serverPkEphemeral)
    if err != nil {
        return nil, nil, nil, err
    }
    if !bytes.Equal(serverPublicKey, o.Curve.PointToBytes(o.serverPkStatic)) {
        return nil, nil, nil, errors.New("server authentication failed")
    }
    // Use clientIdentity to avoid unused variable warning
    _ = clientIdentity // Placeholder for future identity verification
    return privateKey, sessionKey, o.deriveSessionKey(o.Curve.PointToBytes(hardenedKey)), nil
}

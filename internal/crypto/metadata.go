package crypto

import (
	"encoding/json"
)

// encodeMetadata encodes ObjectMetadata to JSON bytes.
func encodeMetadata(m *ObjectMetadata) ([]byte, error) {
	return json.Marshal(m)
}

// decodeMetadata decodes JSON bytes to ObjectMetadata.
func decodeMetadata(data []byte) (*ObjectMetadata, error) {
	var m ObjectMetadata
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

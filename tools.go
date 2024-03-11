package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	//"wallet/poseidon"
	"crypto/sha256"
	//"github.com/vocdoni/arbo"
)

func encodeHexResults(results [][]byte) (string, error) {
	var encoded []string
	for _, result := range results {
		encodedArg := hex.EncodeToString(result)
		encoded = append(encoded, encodedArg)
	}
	return strings.Join(encoded, " "), nil
}

func decrement(encodedValue []byte, num uint32) {
	// Decode the big-endian bytes into a uint32
	decodedValue := binary.BigEndian.Uint32(encodedValue)

	// Perform subtraction
	decodedValue -= num

	// Encode the result back to big-endian bytes
	binary.BigEndian.PutUint32(encodedValue, decodedValue)
}

func increment(encodedValue []byte, num uint32) {
	// Decode the big-endian bytes into a uint32
	decodedValue := binary.BigEndian.Uint32(encodedValue)

	// Perform subtraction
	decodedValue += num

	// Encode the result back to big-endian bytes
	binary.BigEndian.PutUint32(encodedValue, decodedValue)
}

func decodeHexArgs(args ...string) ([][]byte, error) {
	var decoded [][]byte
	for _, arg := range args {
		decodedArg, err := hex.DecodeString(arg)
		if err != nil {
			return nil, fmt.Errorf("error decoding %s: %w", arg, err)
		}
		decoded = append(decoded, decodedArg)
	}
	return decoded, nil
}

func fromJsonMap(body interface{}, data string) interface{} {
	if body != nil {
		return body.(map[string]interface{})[data]
	} else {
		return nil
	}
}

func fromJson(body []byte, data string) interface{} {
	//fmt.Println("Response body:", string(body))
	m := make(map[string]interface{})
	if body == nil {
		return nil
	}
	err := json.Unmarshal(body, &m)
	if err != nil {
		return nil
	}
	dt := m[data]
	return dt
}

func hashData(data []byte) []byte {
	//h2, _ := poseidon.HashBytes(data)
	h2 := sha256.New()
	h2.Write(data)

	result := h2.Sum(nil)

	//result := arbo.BigIntToBytes(32, h2)
	return result
}

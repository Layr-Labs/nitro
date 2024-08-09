package eigenda

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/Layr-Labs/eigenda/encoding"
	"github.com/Layr-Labs/eigenda/encoding/fft"
	"github.com/Layr-Labs/eigenda/encoding/rs"
	"github.com/Layr-Labs/eigenda/encoding/utils/codec"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

/*
	These decodings are translated directly from core EigenDA client codec:
	- https://github.com/Layr-Labs/eigenda/blob/44569ec461c9a1dd1191e7999a72e63bd1e7aba9/api/clients/codecs/ifft_codec.go#L27-L38
*/

func FFT(data []byte) ([]byte, error) {
	dataFr, err := rs.ToFrArray(data)
	if err != nil {
		return nil, fmt.Errorf("error converting data to fr.Element: %w", err)
	}
	dataFrLen := uint64(len(dataFr))
	dataFrLenPow2 := encoding.NextPowerOf2(dataFrLen)

	if dataFrLenPow2 != dataFrLen {
		return nil, fmt.Errorf("data length %d is not a power of 2", dataFrLen)
	}

	maxScale := uint8(math.Log2(float64(dataFrLenPow2)))

	fs := fft.NewFFTSettings(maxScale)

	dataFFTFr, err := fs.FFT(dataFr, false)
	if err != nil {
		return nil, fmt.Errorf("failed to perform FFT: %w", err)
	}

	return rs.ToByteArray(dataFFTFr, dataFrLenPow2*encoding.BYTES_PER_SYMBOL), nil
}

func DecodeiFFTBlob(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("blob has length 0, meaning it is malformed")
	}
	var err error
	data, err = FFT(data)
	if err != nil {
		return nil, fmt.Errorf("error FFTing data: %w", err)
	}

	return GenericDecodeBlob(data)
}

func GenericDecodeBlob(data []byte) ([]byte, error) {
	if len(data) <= 32 {
		return nil, fmt.Errorf("data is not of length greater than 32 bytes: %d", len(data))
	}

	data, err := DecodeBlob(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func DecodeBlob(data []byte) ([]byte, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("blob does not contain 32 header bytes, meaning it is malformed")
	}

	length := binary.BigEndian.Uint32(data[2:6])

	// decode raw data modulo bn254
	decodedData := codec.RemoveEmptyByteFromPaddedBytes(data[32:])

	// get non blob header data
	reader := bytes.NewReader(decodedData)
	rawData := make([]byte, length)
	n, err := reader.Read(rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to copy unpadded data into final buffer, length: %d, bytes read: %d", length, n)
	}
	if uint32(n) != length {
		return nil, fmt.Errorf("data length does not match length prefix")
	}

	return rawData, nil

}

func EncodeBlob(data []byte) ([]byte, error) {
	var err error
	data, err = encodeBlob(data)
	if err != nil {
		return nil, fmt.Errorf("error encoding data: %w", err)
	}

	return IFFT(data)
}

func encodeBlob(rawData []byte) ([]byte, error) {
	codecBlobHeader := make([]byte, 32)
	// first byte is always 0 to ensure the codecBlobHeader is a valid bn254 element
	// encode version byte
	codecBlobHeader[1] = byte(0x0)

	// encode length as uint32
	binary.BigEndian.PutUint32(codecBlobHeader[2:6], uint32(len(rawData))) // uint32 should be more than enough to store the length (approx 4gb)

	// encode raw data modulo bn254
	rawDataPadded := codec.ConvertByPaddingEmptyByte(rawData)

	// append raw data; reassgin avoids copying
	encodedData := codecBlobHeader
	encodedData = append(encodedData, rawDataPadded...)

	return encodedData, nil
}

func IFFT(data []byte) ([]byte, error) {
	// we now IFFT data regardless of the encoding type
	// convert data to fr.Element
	dataFr, err := rs.ToFrArray(data)
	if err != nil {
		return nil, fmt.Errorf("error converting data to fr.Element: %w", err)
	}

	dataFrLen := len(dataFr)
	dataFrLenPow2 := encoding.NextPowerOf2(uint64(dataFrLen))

	// expand data to the next power of 2
	paddedDataFr := make([]fr.Element, dataFrLenPow2)
	for i := 0; i < len(paddedDataFr); i++ {
		if i < len(dataFr) {
			paddedDataFr[i].Set(&dataFr[i])
		} else {
			paddedDataFr[i].SetZero()
		}
	}

	maxScale := uint8(math.Log2(float64(dataFrLenPow2)))

	// perform IFFT
	fs := fft.NewFFTSettings(maxScale)
	dataIFFTFr, err := fs.FFT(paddedDataFr, true)
	if err != nil {
		return nil, fmt.Errorf("failed to perform IFFT: %w", err)
	}

	return rs.ToByteArray(dataIFFTFr, dataFrLenPow2*encoding.BYTES_PER_SYMBOL), nil
}

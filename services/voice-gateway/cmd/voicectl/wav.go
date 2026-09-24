package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

const convertHint = "convert with: afconvert -f WAVE -d LEI16@24000 -c 1 input.m4a output.wav"

// readWAV returns the PCM16 samples of a mono 24 kHz 16-bit WAV file.
func readWAV(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 12 || string(data[0:4]) != "RIFF" || string(data[8:12]) != "WAVE" {
		return nil, errors.New("not a WAV file; " + convertHint)
	}
	var formatOK bool
	for offset := 12; offset+8 <= len(data); {
		id := string(data[offset : offset+4])
		size := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		body := offset + 8
		if body+size > len(data) {
			return nil, errors.New("truncated WAV chunk")
		}
		switch id {
		case "fmt ":
			if size < 16 {
				return nil, errors.New("malformed fmt chunk")
			}
			format := binary.LittleEndian.Uint16(data[body:])
			channels := binary.LittleEndian.Uint16(data[body+2:])
			rate := binary.LittleEndian.Uint32(data[body+4:])
			bits := binary.LittleEndian.Uint16(data[body+14:])
			if format != 1 || channels != 1 || rate != 24000 || bits != 16 {
				return nil, fmt.Errorf("need PCM 16-bit mono 24 kHz, got format %d, %d channels, %d Hz, %d bits; %s",
					format, channels, rate, bits, convertHint)
			}
			formatOK = true
		case "data":
			if !formatOK {
				return nil, errors.New("data chunk before fmt chunk")
			}
			return data[body : body+size], nil
		}
		offset = body + size + size%2
	}
	return nil, errors.New("no audio data in WAV file")
}

// writeWAV saves PCM16 mono 24 kHz samples as a WAV file.
func writeWAV(path string, pcm []byte) error {
	header := make([]byte, 44)
	copy(header[0:], "RIFF")
	binary.LittleEndian.PutUint32(header[4:], uint32(36+len(pcm)))
	copy(header[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(header[16:], 16)
	binary.LittleEndian.PutUint16(header[20:], 1)       // PCM
	binary.LittleEndian.PutUint16(header[22:], 1)       // mono
	binary.LittleEndian.PutUint32(header[24:], 24000)   // sample rate
	binary.LittleEndian.PutUint32(header[28:], 24000*2) // byte rate
	binary.LittleEndian.PutUint16(header[32:], 2)       // block align
	binary.LittleEndian.PutUint16(header[34:], 16)      // bits per sample
	copy(header[36:], "data")
	binary.LittleEndian.PutUint32(header[40:], uint32(len(pcm)))
	return os.WriteFile(path, append(header, pcm...), 0o644)
}

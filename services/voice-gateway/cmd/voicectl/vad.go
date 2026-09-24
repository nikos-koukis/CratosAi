package main

import (
	"encoding/binary"
	"math"
	"time"
)

const (
	// loudRMS is the loudness of speech: the RMS of a chunk, about −32 dBFS.
	// Voice processing on phones levels speech well above it, and leaves
	// noise and the speaker's residual echo well below.
	loudRMS = 800
	// minSpeech of loud audio starts an utterance, so a click or a burst of
	// echo does not interrupt Jarvis (the gateway flushes its answer).
	minSpeech = 200 * time.Millisecond
	// shortGap within the first loud audio is tolerated; longer, it was not
	// speech after all.
	shortGap = 150 * time.Millisecond
	// endOfSpeech is the pause that ends an utterance.
	endOfSpeech = 600 * time.Millisecond
	// prefixPadding of audio before speech starts is kept, so the echo does
	// not cut off the first syllable.
	prefixPadding = 300 * time.Millisecond
)

// vad finds utterances in PCM16 mono 24 kHz audio by loudness, in the
// manner of a provider's server VAD.
type vad struct {
	speaking bool
	// Before speech is confirmed: the audio since it got loud.
	pending []byte
	loudFor time.Duration
	// Quiet since the last loud chunk (in pending, or while speaking).
	quietFor time.Duration
	prefix   []byte
	// The utterance being spoken, then the last one.
	recording []byte
}

// push adds a chunk; it reports whether speech started or ended with it.
func (v *vad) push(pcm []byte) (started, ended bool) {
	d := pcmDuration(pcm)
	loud := rms(pcm) >= loudRMS
	switch {
	case v.speaking:
		v.recording = append(v.recording, pcm...)
		if loud {
			v.quietFor = 0
		} else if v.quietFor += d; v.quietFor >= endOfSpeech {
			v.speaking, v.quietFor = false, 0
			return false, true
		}
	case loud:
		v.pending = append(v.pending, pcm...)
		v.loudFor += d
		v.quietFor = 0
		if v.loudFor >= minSpeech {
			v.speaking, started = true, true
			v.recording = append(append([]byte(nil), v.prefix...), v.pending...)
			v.pending, v.prefix, v.loudFor = nil, nil, 0
		}
	case len(v.pending) > 0:
		v.pending = append(v.pending, pcm...)
		if v.quietFor += d; v.quietFor >= shortGap {
			// A blip: it becomes part of the padding.
			v.prefix = lastOf(append(v.prefix, v.pending...), prefixPadding)
			v.pending, v.loudFor, v.quietFor = nil, 0, 0
		}
	default:
		v.prefix = lastOf(append(v.prefix, pcm...), prefixPadding)
	}
	return started, false
}

// pcmDuration is the length of PCM16 mono 24 kHz audio (48 bytes a millisecond).
func pcmDuration(pcm []byte) time.Duration {
	return time.Duration(len(pcm)/2) * time.Second / 24000
}

// lastOf keeps the last d of the audio.
func lastOf(pcm []byte, d time.Duration) []byte {
	keep := int(d.Seconds()*24000) * 2
	if len(pcm) <= keep {
		return pcm
	}
	return append([]byte(nil), pcm[len(pcm)-keep:]...)
}

func rms(pcm []byte) float64 {
	n := len(pcm) / 2
	if n == 0 {
		return 0
	}
	var sum float64
	for i := 0; i < n; i++ {
		s := float64(int16(binary.LittleEndian.Uint16(pcm[2*i:])))
		sum += s * s
	}
	return math.Sqrt(sum / float64(n))
}

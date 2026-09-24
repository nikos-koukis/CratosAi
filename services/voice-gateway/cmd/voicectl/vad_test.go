package main

import (
	"encoding/binary"
	"math"
	"testing"
	"time"
)

// sine is d of a 200 Hz tone with the given peak, as PCM16 mono 24 kHz.
func sine(d time.Duration, peak float64) []byte {
	samples := int(d.Seconds() * 24000)
	pcm := make([]byte, 2*samples)
	for i := range samples {
		binary.LittleEndian.PutUint16(pcm[2*i:], uint16(int16(peak*math.Sin(2*math.Pi*200*float64(i)/24000))))
	}
	return pcm
}

// feed pushes audio in 20 ms frames, as the app sends it; it returns the
// offsets (from the start of audio) at which speech started and ended.
func feed(v *vad, audio []byte) (started, ended []time.Duration) {
	const frame = 960
	for offset := 0; offset < len(audio); offset += frame {
		s, e := v.push(audio[offset:min(offset+frame, len(audio))])
		at := pcmDuration(audio[:min(offset+frame, len(audio))])
		if s {
			started = append(started, at)
		}
		if e {
			ended = append(ended, at)
		}
	}
	return started, ended
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

const (
	speechPeak = 3000 // RMS ≈ 2100
	noisePeak  = 700  // RMS ≈ 500: peaks the old detector took for speech
)

func TestClicksEchoAndNoiseAreNotSpeech(t *testing.T) {
	var v vad
	started, _ := feed(&v, concat(
		sine(time.Second, noisePeak),
		sine(40*time.Millisecond, speechPeak), // a click
		sine(time.Second, 0),
		sine(140*time.Millisecond, speechPeak), // a burst of residual echo
		sine(200*time.Millisecond, 0),
		sine(100*time.Millisecond, speechPeak), // two bursts, each too short
		sine(200*time.Millisecond, 0),
		sine(100*time.Millisecond, speechPeak),
		sine(time.Second, noisePeak),
	))
	if len(started) != 0 {
		t.Fatalf("speech started at %v", started)
	}
}

func TestAnUtteranceIsRecordedWholeWithItsLeadIn(t *testing.T) {
	var v vad
	lead := sine(500*time.Millisecond, noisePeak)
	words := concat(
		sine(700*time.Millisecond, speechPeak),
		sine(400*time.Millisecond, 0), // a pause between words
		sine(500*time.Millisecond, speechPeak),
	)
	started, ended := feed(&v, concat(lead, words, sine(time.Second, 0)))
	if len(started) != 1 || started[0] != 500*time.Millisecond+minSpeech {
		t.Fatalf("started at %v, want once after %v of speech", started, minSpeech)
	}
	if len(ended) != 1 || ended[0] != pcmDuration(lead)+pcmDuration(words)+endOfSpeech {
		t.Fatalf("ended at %v, want once, %v after the last word", ended, endOfSpeech)
	}
	// The lead-in padding, all the words, then the pause that ended them.
	want := pcmDuration(lead[len(lead)-len(lastOf(lead, prefixPadding)):]) + pcmDuration(words) + endOfSpeech
	if got := pcmDuration(v.recording); got != want {
		t.Fatalf("recorded %v, want %v", got, want)
	}
	if string(v.recording[:len(lastOf(lead, prefixPadding))]) != string(lastOf(lead, prefixPadding)) {
		t.Fatal("the recording does not start with the lead-in")
	}
}

func TestSpeechAfterABlipKeepsTheBlipAsLeadIn(t *testing.T) {
	var v vad
	blip := sine(60*time.Millisecond, speechPeak)
	lead := concat(blip, sine(200*time.Millisecond, 0)) // shorter than the padding: all kept
	started, ended := feed(&v, concat(lead, sine(400*time.Millisecond, speechPeak), sine(time.Second, 0)))
	if len(started) != 1 || len(ended) != 1 {
		t.Fatalf("started %v, ended %v", started, ended)
	}
	if got, want := pcmDuration(v.recording), pcmDuration(lead)+400*time.Millisecond+endOfSpeech; got != want {
		t.Fatalf("recorded %v, want %v", got, want)
	}
	if string(v.recording[:len(blip)]) != string(blip) {
		t.Fatal("the recording does not start with the blip")
	}
}

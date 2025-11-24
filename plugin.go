package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
)

// Identity represents an age-plugin-op identity.
type Identity struct {
}

// NewIdentity creates a new Identity from decoded identity data.
func NewIdentity(data []byte) (age.Identity, error) {
	return &Identity{}, nil
}

// Unwrap decrypts a file key from one of the provided stanzas.
func (i *Identity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	ctx := context.Background()

	allKeys, err := listOPSSHKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list SSH keys from 1Password: %w", err)
	}

	var joinedErr error
	for _, stanza := range stanzas {
		if len(stanza.Args) == 0 {
			continue
		}

		fingerprintPrefix := stanza.Args[0]
		expectedPrefix := "SHA256:" + fingerprintPrefix

		for _, key := range allKeys {
			if !strings.HasPrefix(key.AdditionalInformation, expectedPrefix) {
				continue
			}

			privateKey, err := fetchOPSSHPrivateKey(ctx, key.ID)
			if err != nil {
				joinedErr = errors.Join(joinedErr, fmt.Errorf("failed to fetch key %s: %w", key.ID, err))
				continue
			}

			identity, err := agessh.ParseIdentity([]byte(privateKey))
			if err != nil {
				joinedErr = errors.Join(joinedErr, fmt.Errorf("failed to parse key %s: %w", key.ID, err))
				continue
			}

			fileKey, err := identity.Unwrap(stanzas)
			if errors.Is(err, age.ErrIncorrectIdentity) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt with key %s: %w", key.ID, err)
			}
			return fileKey, nil
		}
	}

	if joinedErr != nil {
		return nil, joinedErr
	}

	return nil, age.ErrIncorrectIdentity
}

type opItemSummary struct {
	ID                    string `json:"id"`
	AdditionalInformation string `json:"additional_information"`
}

type opField struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
	Value string `json:"value"`
}

func listOPSSHKeys(ctx context.Context) ([]opItemSummary, error) {
	cmd := exec.CommandContext(ctx, "op", "item", "list", "--categories", "SSH Key", "--format=json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("op item list: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	var summaries []opItemSummary
	if err := json.Unmarshal(stdout.Bytes(), &summaries); err != nil {
		return nil, fmt.Errorf("decode op item list: %w", err)
	}

	keys := make([]opItemSummary, 0, len(summaries))
	for _, item := range summaries {
		if item.ID != "" {
			keys = append(keys, item)
		}
	}

	return keys, nil
}

func fetchOPSSHPrivateKey(ctx context.Context, id string) (string, error) {
	cmd := exec.CommandContext(ctx, "op", "item", "get", id, "--format=json", "--fields", "type=SSHKEY")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("op item get: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	var field opField
	if err := json.Unmarshal(stdout.Bytes(), &field); err != nil {
		return "", fmt.Errorf("decode op item: %w", err)
	}

	privateKey := strings.TrimSpace(field.Value)
	if privateKey != "" {
		return privateKey, nil
	}

	return "", fmt.Errorf("private key not found in item %s", id)
}

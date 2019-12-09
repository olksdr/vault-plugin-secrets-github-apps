package gh

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestConfig(t *testing.T) {
	t.Parallel()

	b, reqS := getTestBackend(t)
	testConfigRead(t, b, reqS, nil)

	config := map[string]interface{}{
		"private_key": "// private key rsa //",
		"app_id":      12345,
	}

	testConfigUpdate(t, b, reqS, config)

	expected := map[string]interface{}{
		"app_id": 12345,
	}
	testConfigRead(t, b, reqS, expected)
	testConfigUpdate(t, b, reqS, map[string]interface{}{
		"app_id": 54321,
	})

	expected["app_id"] = 54321
	testConfigRead(t, b, reqS, expected)
}

func testConfigUpdate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}

func testConfigRead(t *testing.T, b logical.Backend, s logical.Storage, expected map[string]interface{}) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   s,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp == nil && expected == nil {
		return
	}

	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	if len(expected) != len(resp.Data) {
		t.Errorf("read data mismatch (expected %d values, got %d)", len(expected), len(resp.Data))
	}

	for k, expectedV := range expected {
		actualV, ok := resp.Data[k]

		if !ok {
			t.Errorf(`expected data["%s"] = %v but was not included in read output"`, k, expectedV)
		} else if expectedV != actualV {
			t.Errorf(`expected data["%s"] = %v, instead got %v"`, k, expectedV, actualV)
		}
	}

	if t.Failed() {
		t.FailNow()
	}
}

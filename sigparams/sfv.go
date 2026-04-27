package sigparams

import "github.com/dunglas/httpsfv"

var defaultSort = []string{"alg", "created", "expires", "keyid", "nonce", "tag"}

// SFV converts the params to an HTTP structured field value sorting them based on the sortKeys arguments list.
// If there aren't any sortKeys, the defaultSort will be used.
func (p Params) SFV(sortKeys ...string) *httpsfv.InnerList {
	// Construct the Signature Parameters field (@signature-params)
	// See: https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3
	sigParams := httpsfv.InnerList{
		Items:  make([]httpsfv.Item, len(p.CoveredComponents)),
		Params: httpsfv.NewParams(),
	}

	if len(sortKeys) == 0 {
		sortKeys = defaultSort
	}

	for i, cc := range p.CoveredComponents {
		sigParams.Items[i] = httpsfv.NewItem(cc)
	}

	// Using the sort order shown in the initial contents for the "HTTP Signature Metadata Parameters" registry
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-initial-contents-2
	for _, param := range sortKeys {
		var val any
		switch param {
		case "alg":
			if p.Alg != "" {
				val = p.Alg
			}
		case "created":
			if !p.Created.IsZero() {
				val = p.Created.Unix()
			}
		case "expires":
			if !p.Expires.IsZero() {
				val = p.Expires.Unix()
			}
		case "keyid":
			if p.KeyID != "" {
				val = p.KeyID
			}
		case "nonce":
			if p.Nonce != "" {
				val = p.Nonce
			}
		case "tag":
			if p.Tag != "" {
				val = p.Tag
			}
		}
		if val != nil {
			sigParams.Params.Add(param, val)
		}
	}

	return &sigParams
}

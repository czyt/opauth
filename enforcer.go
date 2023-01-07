/*
 * MIT License
 *
 * Copyright (c) 2023 czyt
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package opauth

import (
	"context"
	"github.com/open-policy-agent/opa/rego"
)

type EvalInputGetter interface {
	GetEvalInput(param ...any) (map[string]any, error)
}

type Enforcer struct {
	engine rego.PreparedEvalQuery
	input  EvalInputGetter
	query  string
}

func NewEnforcer(ctx context.Context, policyContent, name, query string, inputGetter EvalInputGetter) (*Enforcer, error) {
	engine, err := rego.New(
		rego.Query(query),
		rego.Module(name, policyContent),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	return &Enforcer{
		engine: engine,
		query:  query,
		input:  inputGetter,
	}, nil
}

func (e *Enforcer) ValidateAllowed(ctx context.Context) (bool, error) {
	evalResult, err := e.Validate(ctx)
	if err != nil {
		return false, err
	}
	return evalResult.Allowed(), nil
}

func (e *Enforcer) Validate(ctx context.Context) (rego.ResultSet, error) {
	input, err := e.input.GetEvalInput()
	if err != nil {
		return nil, err
	}
	evalResult, err := e.engine.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, err
	}
	return evalResult, nil
}

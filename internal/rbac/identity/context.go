package identity

import "context"

type callerContextKey struct{}

func WithCallerContext(ctx context.Context, caller CallerContext) context.Context {
	return context.WithValue(ctx, callerContextKey{}, caller)
}

func CallerFromContext(ctx context.Context) (CallerContext, bool) {
	if ctx == nil {
		return CallerContext{}, false
	}

	caller, ok := ctx.Value(callerContextKey{}).(CallerContext)
	return caller, ok
}

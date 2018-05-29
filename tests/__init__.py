"""Tests for jars."""


def assert_args(call_args, *args, **kwargs):
    """Check if args contain elements in args and kwargs."""
    c_args, c_kwargs = call_args

    # check positional args
    for arg in args:
        assert arg in c_args

    # check keyword args
    for name, value in kwargs.items():
        assert c_kwargs[name] == value


def any_args(call_arg_list, *args, **expected_args):
    """Check if arg list contains elements in args and kwargs."""
    for call_args in call_arg_list:
        c_args, c_kwargs = call_args

        # check positional args
        c_args_match = all((arg in c_args for arg in args))

        # check keyword args
        c_kargs_match = all(
            (c_kwargs[karg] == value for karg, value in expected_args.items()))

        if c_args_match and c_kargs_match:
            return True
    return False

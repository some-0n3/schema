"""schema is a library for validating Python data structures, such as those
obtained from config-files, forms, external services or command-line
parsing, converted from JSON/YAML (or something else) to Python data-types."""

import re

try:
    from contextlib import ExitStack
except ImportError:
    from contextlib2 import ExitStack

__version__ = "0.7.0"
__all__ = [
    "Schema",
    "And",
    "Or",
    "Regex",
    "Optional",
    "Use",
    "Forbidden",
    "Const",
    "Literal",
    "SchemaError",
    "SchemaWrongKeyError",
    "SchemaMissingKeyError",
    "SchemaForbiddenKeyError",
    "SchemaUnexpectedTypeError",
    "SchemaOnlyOneAllowedError",
]


class SchemaError(Exception):
    """Error during Schema validation."""

    def __init__(self, autos, errors=None):
        self.autos = autos if type(autos) is list else [autos]
        self.errors = errors if type(errors) is list else [errors]
        Exception.__init__(self, self.code)

    @property
    def code(self):
        """
        Removes duplicates values in auto and error list.
        parameters.
        """

        def uniq(seq):
            """
            Utility function that removes duplicate.
            """
            seen = set()
            seen_add = seen.add
            # This way removes duplicates while preserving the order.
            return [x for x in seq if x not in seen and not seen_add(x)]

        data_set = uniq(i for i in self.autos if i is not None)
        error_list = uniq(i for i in self.errors if i is not None)
        if error_list:
            return "\n".join(error_list)
        return "\n".join(data_set)


class SchemaWrongKeyError(SchemaError):
    """Error Should be raised when an unexpected key is detected within the
    data set being."""

    pass


class SchemaMissingKeyError(SchemaError):
    """Error should be raised when a mandatory key is not found within the
    data set being validated"""

    pass


class SchemaOnlyOneAllowedError(SchemaError):
    """Error should be raised when an only_one Or key has multiple matching candidates"""

    pass


class SchemaForbiddenKeyError(SchemaError):
    """Error should be raised when a forbidden key is found within the
    data set being validated, and its value matches the value that was specified"""

    pass


class SchemaUnexpectedTypeError(SchemaError):
    """Error should be raised when a type mismatch is detected within the
    data set being validated."""

    pass


class Base(object):
    """Base class for all schemas."""

    def __init__(self, error=None, name=None, description=None):
        self._error = error
        self._name = name
        self._description = description

    @property
    def name(self):
        return self._name

    @property
    def description(self):
        return self._description

    @staticmethod
    def _is_optional_type(s):
        """Return True if the given key is optional (does not have to be found)"""
        return any(isinstance(s, optional_type) for optional_type in [Optional, Hook])

    def _prepend_schema_name(self, message):
        """
        If a custom schema name has been defined, prepends it to the error
        message that gets raised when a schema error occurs.
        """
        if self._name:
            message = "{0!r} {1!s}".format(self._name, message)
        return message


# Atomic schemas


class _Type(Base):
    def __init__(self, typ, **kwargs):
        super(_Type, self).__init__(**kwargs)
        self._type = typ

    def validate(self, data):
        if isinstance(data, self._type) and not (isinstance(data, bool) and self._type == int):
            return data
        err = self._error
        message = "%r should be instance of %r" % (data, self._type.__name__)
        message = self._prepend_schema_name(message)
        raise SchemaUnexpectedTypeError(message, err.format(data) if err else None)


class _Value(Base):
    def __init__(self, value, **kwargs):
        super(_Value, self).__init__(**kwargs)
        self._value = value

    def validate(self, data):
        if self._value == data:
            return data
        if isinstance(self._value, Literal):
            if self._value.schema == data:
                return data
        message = "%r does not match %r" % (self._value, data)
        message = self._prepend_schema_name(message)
        raise SchemaError(message, self._error.format(data) if self._error else None)


class Regex(Base):
    """
    Enables schema.py to validate string using regular expressions.
    """

    # Map all flags bits to a more readable description
    NAMES = [
        "re.ASCII",
        "re.DEBUG",
        "re.VERBOSE",
        "re.UNICODE",
        "re.DOTALL",
        "re.MULTILINE",
        "re.LOCALE",
        "re.IGNORECASE",
        "re.TEMPLATE",
    ]

    def __init__(self, pattern_str, flags=0, error=None):
        super(Regex, self).__init__(error=error)
        self._pattern_str = pattern_str
        flags_list = [Regex.NAMES[i] for i, f in enumerate("{0:09b}".format(flags)) if f != "0"]  # Name for each bit

        if flags_list:
            self._flags_names = ", flags=" + "|".join(flags_list)
        else:
            self._flags_names = ""

        self._pattern = re.compile(pattern_str, flags=flags)

    def __repr__(self):
        return "%s(%r%s)" % (self.__class__.__name__, self._pattern_str, self._flags_names)

    @property
    def pattern_str(self):
        """The pattern for the represented regular expression"""
        return self._pattern_str

    def validate(self, data):
        """
        Validated data using defined regex.
        :param data: data to be validated
        :return: return validated data.
        """
        e = self._error

        try:
            if self._pattern.search(data):
                return data
            raise SchemaError("%r does not match %r" % (self, data), e)
        except TypeError:
            raise SchemaError("%r is not string nor buffer" % data, e)


def _callable_str(callable_):
    if hasattr(callable_, "__name__"):
        return callable_.__name__
    return str(callable_)


class _Check(Base):
    """Validation for callables."""

    def __init__(self, callable_, **kwargs):
        super(_Check, self).__init__(**kwargs)
        self._callable = callable_

    def validate(self, data):
        f = _callable_str(self._callable)
        try:
            if self._callable(data):
                return data
        except SchemaError as x:
            raise SchemaError([None] + x.autos, [self._error] + x.errors)
        except BaseException as x:
            message = "%s(%r) raised %r" % (f, data, x)
            message = self._prepend_schema_name(message)
            raise SchemaError(message, self._error.format(data) if self._error else None)
        message = "%s(%r) should evaluate to True" % (f, data)
        message = self._prepend_schema_name(message)
        raise SchemaError(message, self._error)


class Use(Base):
    """
    For more general use cases, you can use the Use class to transform
    the data while it is being validate.
    """

    def __init__(self, callable_, error=None):
        super(Use, self).__init__(error=error)
        if not callable(callable_):
            raise TypeError("Expected a callable, not %r" % callable_)
        self._callable = callable_

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self._callable)

    def validate(self, data):
        try:
            return self._callable(data)
        except SchemaError as x:
            raise SchemaError([None] + x.autos, [self._error.format(data) if self._error else None] + x.errors)
        except BaseException as x:
            f = _callable_str(self._callable)
            raise SchemaError("%s(%r) raised %r" % (f, data, x), self._error.format(data) if self._error else None)


# Mixin schemas

COMPARABLE, CALLABLE, VALIDATOR, TYPE, DICT, ITERABLE = range(6)


def _priority(s):
    """Return priority for a given object."""
    if type(s) in (list, tuple, set, frozenset):
        return ITERABLE
    if type(s) is dict:
        return DICT
    if issubclass(type(s), type):
        return TYPE
    if isinstance(s, Literal):
        return COMPARABLE
    if hasattr(s, "validate"):
        return VALIDATOR
    if callable(s):
        return CALLABLE
    return COMPARABLE


def _flattable(schema):
    """Return if the wrapping can be ommitted."""
    return schema in (schemify, Schema, Forbidden, Optional)


def _empty(schema):
    """Return if a schema can be ommitted."""
    if isinstance(schema, Schema):
        return type(schema).validate == Schema.validate
    return isinstance(schema, _Wrapper) and schema._error is None


def schemify(schema, error=None, ignore_extra_keys=False, name=None):
    """Create a minimalistic schema (instance of ``Base``)."""
    # try to avoid unnecessary wrappings
    if isinstance(schema, Base):
        while _empty(schema):
            schema = schema._worker
    if hasattr(schema, "validate"):
        return _Wrapper(schema, error=error, name=name) if error else schema

    flavor = _priority(schema)
    if flavor == ITERABLE:
        return _Iterable(schema, schema=schemify, error=error, ignore_extra_keys=ignore_extra_keys, name=name)
    if flavor == DICT:
        return _Dict(schema, schema=schemify, error=error, ignore_extra_keys=ignore_extra_keys, name=name)
    if flavor == TYPE:
        return _Type(schema, error=error, name=name)
    if flavor == CALLABLE:
        return _Check(schema, error=error, name=name)
    return _Value(schema, error=error, name=name)


def _schema_args(kw):
    """Parse `schema`, `error` and `ignore_extra_keys`."""
    if not set(kw).issubset({"error", "schema", "ignore_extra_keys", "name", "description"}):
        diff = {"error", "schema", "ignore_extra_keys", "name"}.difference(kw)
        raise TypeError("Unknown keyword arguments %r" % list(diff))
    schema = kw.get("schema", schemify)
    if _flattable(schema):
        schema = schemify
    error = kw.get("error")
    ignore = kw.get("ignore_extra_keys", False)
    name = kw.get("name", None)
    description = kw.get("description", None)
    return schema, error, ignore, name, description


class And(Base):
    """
    Utility function to combine validation directives in AND Boolean fashion.
    """

    def __init__(self, *args, **kw):
        self._args = args
        schema, error, ignore, name, descr = _schema_args(kw)
        super(And, self).__init__(error=error, name=name, description=descr)
        # You can pass your inherited Schema class.
        self._schema_seq = [schema(s, error=error, ignore_extra_keys=ignore) for s in args]

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, ", ".join(repr(a) for a in self._args))

    @property
    def args(self):
        """The provided parameters"""
        return self._args

    def validate(self, data):
        """
        Validate data using defined sub schema/expressions ensuring all
        values are valid.
        :param data: to be validated with sub defined schemas.
        :return: returns validated data
        """
        for schema in self._schema_seq:
            data = schema.validate(data)
        return data


class Or(And):
    """Utility function to combine validation directives in a OR Boolean
    fashion."""

    def __init__(self, *args, **kwargs):
        self.only_one = kwargs.pop("only_one", False)
        self.match_count = 0
        super(Or, self).__init__(*args, **kwargs)

    def reset(self):
        failed = self.match_count > 1 and self.only_one
        self.match_count = 0
        if failed:
            raise SchemaOnlyOneAllowedError(["There are multiple keys present " + "from the %r condition" % self])

    def validate(self, data):
        """
        Validate data using sub defined schema/expressions ensuring at least
        one value is valid.
        :param data: data to be validated by provided schema.
        :return: return validated data if not validation
        """
        autos, errors = [], []
        for schema in self._schema_seq:
            try:
                validation = schema.validate(data)
                self.match_count += 1
                if self.match_count > 1 and self.only_one:
                    break
                return validation
            except SchemaError as _x:
                autos, errors = _x.autos, _x.errors
        raise SchemaError(
            ["%r did not validate %r" % (self, data)] + autos,
            [self._error.format(data) if self._error else None] + errors,
        )


class _Iterable(Base):
    def __init__(self, iterable, **kwargs):
        schema, error, ignore, name, descr = _schema_args(kwargs)
        super(_Iterable, self).__init__(error=error, name=name, description=descr)
        self._type_check = schema(type(iterable), error=error)
        self._schema = Or(*iterable, error=error, schema=schema, ignore_extra_keys=ignore)

    def validate(self, data):
        data = self._type_check.validate(data)
        return type(data)(self._schema.validate(d) for d in data)


class _Dict(Base):
    def __init__(self, dct, **kwargs):
        schema, error, ignore, name, descr = _schema_args(kwargs)
        super(_Dict, self).__init__(error=error, name=name, description=descr)
        self._ignore_extra_keys = ignore
        sorted_keys = sorted(dct, key=self._dict_key_priority)
        self._sorted = [
            (k, schema(k, error=error), schema(dct[k], error=error, ignore_extra_keys=ignore)) for k in sorted_keys
        ]
        self._casting = schema(dict, error=error)
        self._required = set(k for k in dct if not self._is_optional_type(k))
        self._defaults = set(k for k in dct if type(k) is Optional and hasattr(k, "default"))
        self._resets = tuple(k for k in sorted_keys if hasattr(k, "reset"))

    @property
    def ignore_extra_keys(self):
        return self._ignore_extra_keys

    @staticmethod
    def _dict_key_priority(s):
        """Return priority for a given key object."""
        if isinstance(s, Hook):
            return _priority(s._schema) - 0.5
        if isinstance(s, Optional):
            return _priority(s._schema) + 0.5
        return _priority(s)

    def validate(self, data):
        exitstack = ExitStack()
        e = self._error
        data = self._casting.validate(data)
        new = type(data)()  # new - is a dict of the validated values
        coverage = set()  # matched schema keys
        # for each key and value find a schema entry matching them, if any
        for skey in self._resets:
            exitstack.callback(skey.reset)
        with exitstack:
            # Evaluate dictionaries last
            data_items = sorted(data.items(), key=lambda value: isinstance(value[1], dict))
            for key, value in data_items:
                for skey, key_sc, val_sc in self._sorted:
                    try:
                        nkey = key_sc.validate(key)
                    except SchemaError:
                        pass
                    else:
                        if isinstance(skey, Hook):
                            # As the content of the value makes little sense for
                            # keys with a hook, we reverse its meaning:
                            # we will only call the handler if the value does match
                            # In the case of the forbidden key hook,
                            # we will raise the SchemaErrorForbiddenKey exception
                            # on match, allowing for excluding a key only if its
                            # value has a certain type, and allowing Forbidden to
                            # work well in combination with Optional.
                            try:
                                nvalue = val_sc.validate(value)
                            except SchemaError:
                                continue
                            skey.handler(nkey, data, e)
                        else:
                            if isinstance(skey, Hook):
                                # As the content of the value makes little sense for
                                # keys with a hook, we reverse its meaning:
                                # we will only call the handler if the value does match
                                # In the case of the forbidden key hook,
                                # we will raise the SchemaErrorForbiddenKey exception
                                # on match, allowing for excluding a key only if its
                                # value has a certain type, and allowing Forbidden to
                                # work well in combination with Optional.
                                try:
                                    nvalue = val_sc.validate(value)
                                except SchemaError:
                                    continue
                                skey.handler(nkey, data, e)
                            else:
                                try:
                                    nvalue = val_sc.validate(value)
                                except SchemaError as x:
                                    k = "Key '%s' error:" % nkey
                                    message = self._prepend_schema_name(k)
                                    raise SchemaError([message] + x.autos, [e] + x.errors)
                                else:
                                    new[nkey] = nvalue
                                    coverage.add(skey)
                                    break

            if not self._required.issubset(coverage):
                missing_keys = self._required - coverage
                s_missing_keys = ", ".join(sorted(repr(k) for k in missing_keys))
                message = "Missing key%s: %s" % (_plural_s(missing_keys), s_missing_keys)
                message = self._prepend_schema_name(message)
                raise SchemaMissingKeyError(message, e)
            if not self._ignore_extra_keys and (len(new) != len(data)):
                wrong_keys = set(data.keys()) - set(new.keys())
                s_wrong_keys = ", ".join(sorted(repr(k) for k in wrong_keys))
                message = "Wrong key%s %s in %r" % (_plural_s(wrong_keys), s_wrong_keys, data)
                message = self._prepend_schema_name(message)
                raise SchemaWrongKeyError(message, e.format(data) if e else None)
            # Apply default-having optionals that haven't been used:
            for default in self._defaults - coverage:
                new[default.key] = default.default() if callable(default.default) else default.default

            return new


class _Wrapper(Base):
    """Helper class to wrap a error around a validator."""

    def __init__(self, validator, error=None, name=None, description=None):
        super(_Wrapper, self).__init__(error=error, name=name, description=description)
        self._worker = schemify(validator)

    def validate(self, data):
        try:
            return self._worker.validate(data)
        except SchemaError as x:
            raise SchemaError([None] + x.autos, [self._error] + x.errors)
        except BaseException as x:
            message = "%r.validate(%r) raised %r" % (self._worker, data, x)
            message = self._prepend_schema_name(message)
            raise SchemaError(message, self._error.format(data) if self._error else None)


class Schema(Base):
    """
    Entry point of the library, use this class to instantiate validation
    schema for the data that will be validated.
    """

    def __init__(self, schema, error=None, ignore_extra_keys=False, name=None, description=None, as_reference=False):
        super(Schema, self).__init__(error=error, name=name, description=description)
        self._schema = schema
        flavor = _priority(schema)
        if flavor == ITERABLE:
            self._worker = _Iterable(
                schema, schema=type(self), error=error, ignore_extra_keys=ignore_extra_keys, name=name
            )
        elif flavor == DICT:
            self._worker = _Dict(
                schema,
                schema=type(self),
                error=error,
                ignore_extra_keys=ignore_extra_keys,
                name=name,
                description=description,
            )
        elif flavor == TYPE:
            self._worker = _Type(schema, error=error, name=name, description=description)
        elif flavor == VALIDATOR:
            self._worker = _Wrapper(schema, error=error, name=name, description=description)
        elif flavor == CALLABLE:
            self._worker = _Check(schema, error=error, name=name, description=description)
        else:
            self._worker = _Value(schema, error=error, name=name, description=description)
        self._ignore_extra_keys = ignore_extra_keys
        # Ask json_schema to create a definition for this schema and use it as part of another
        self.as_reference = as_reference
        if as_reference and name is None:
            raise ValueError("Schema used as reference should have a name")

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self._schema)

    @property
    def schema(self):
        return self._schema

    @property
    def ignore_extra_keys(self):
        return self._ignore_extra_keys

    def is_valid(self, data):
        """Return whether the given data has passed all the validations
        that were specified in the given schema.
        """
        try:
            self.validate(data)
            return True
        except SchemaError:
            return False

    def validate(self, data):
        return self._worker.validate(data)

    def json_schema(self, schema_id, use_refs=False):
        """Generate a draft-07 JSON schema dict representing the Schema.
        This method can only be called when the Schema's value is a dict.
        This method must be called with a schema_id.

        :param schema_id: The value of the $id on the main schema
        :param use_refs: Enable reusing object references in the resulting JSON schema.
                         Schemas with references are harder to read by humans, but are a lot smaller when there
                         is a lot of reuse
        """

        seen = dict()  # For use_refs
        definitions_by_name = {}

        def _json_schema(schema, is_main_schema=True, description=None, allow_reference=True):
            Schema = self.__class__

            def _create_or_use_ref(return_dict):
                """If not already seen, return the provided part of the schema unchanged.
                If already seen, give an id to the already seen dict and return a reference to the previous part
                of the schema instead.
                """
                if not use_refs or is_main_schema:
                    return return_schema

                hashed = hash(repr(sorted(return_dict.items())))

                if hashed not in seen:
                    seen[hashed] = return_dict
                    return return_dict
                else:
                    id_str = "#" + str(hashed)
                    seen[hashed]["$id"] = id_str
                    return {"$ref": id_str}

            def _get_type_name(python_type):
                """Return the JSON schema name for a Python type"""
                if python_type == str:
                    return "string"
                elif python_type == int:
                    return "integer"
                elif python_type == float:
                    return "number"
                elif python_type == bool:
                    return "boolean"
                elif python_type == list:
                    return "array"
                elif python_type == dict:
                    return "object"
                return "string"

            def _to_schema(s, ignore_extra_keys):
                if not isinstance(s, Schema):
                    return Schema(s, ignore_extra_keys=ignore_extra_keys)

                return s

            s = schema.schema
            i = schema.ignore_extra_keys
            flavor = _priority(s)

            return_schema = {}
            if description:
                return_schema["description"] = description

            if flavor != DICT and is_main_schema:
                raise ValueError("The main schema must be a dict.")

            if flavor == TYPE:
                # Handle type
                return_schema["type"] = _get_type_name(s)
            elif flavor == ITERABLE:
                # Handle arrays or dict schema

                return_schema["type"] = "array"
                if len(s) == 1:
                    return_schema["items"] = _json_schema(_to_schema(s[0], i), is_main_schema=False)
                elif len(s) > 1:
                    return_schema["items"] = _json_schema(Schema(Or(*s)), is_main_schema=False)
            elif isinstance(s, Or):
                # Handle Or values

                # Check if we can use an enum
                if all(priority == COMPARABLE for priority in [_priority(value) for value in s.args]):
                    or_values = [str(s) if isinstance(s, Literal) else s for s in s.args]
                    # All values are simple, can use enum or const
                    if len(or_values) == 1:
                        return_schema["const"] = or_values[0]
                        return return_schema
                    return_schema["enum"] = or_values
                else:
                    # No enum, let's go with recursive calls
                    any_of_values = []
                    for or_key in s.args:
                        new_value = _json_schema(_to_schema(or_key, i), is_main_schema=False)
                        if new_value not in any_of_values:
                            any_of_values.append(new_value)
                    return_schema["anyOf"] = any_of_values
            elif isinstance(s, And):
                # Handle And values
                all_of_values = []
                for and_key in s.args:
                    new_value = _json_schema(_to_schema(and_key, i), is_main_schema=False)
                    if new_value != {} and new_value not in all_of_values:
                        all_of_values.append(new_value)
                return_schema["allOf"] = all_of_values
            elif flavor == COMPARABLE:
                return_schema["const"] = str(s)
            elif flavor == VALIDATOR and type(s) == Regex:
                return_schema["type"] = "string"
                return_schema["pattern"] = s.pattern_str
            else:
                if flavor != DICT:
                    # If not handled, do not check
                    return return_schema

                # Schema is a dict

                # Check if we have to create a common definition and use as reference
                if allow_reference and schema.as_reference:
                    # Generate sub schema if not already done
                    if schema.name not in definitions_by_name:
                        definitions_by_name[schema.name] = {}  # Avoid infinite loop
                        definitions_by_name[schema.name] = _json_schema(
                            schema, is_main_schema=False, allow_reference=False
                        )

                    return_schema["$ref"] = "#/definitions/" + schema.name
                else:
                    required_keys = []
                    expanded_schema = {}
                    for key in s:
                        if isinstance(key, Hook):
                            continue

                        def _get_key_description(key):
                            """Get the description associated to a key (as specified in a Literal object). Return None if not a Literal"""
                            if isinstance(key, Optional):
                                return _get_key_description(key.schema)

                            if isinstance(key, Literal):
                                return key.description

                            return None

                        def _get_key_name(key):
                            """Get the name of a key (as specified in a Literal object). Return the key unchanged if not a Literal"""
                            if isinstance(key, Optional):
                                return _get_key_name(key.schema)

                            if isinstance(key, Literal):
                                return key.schema

                            return key

                        sub_schema = _to_schema(s[key], ignore_extra_keys=i)
                        key_name = _get_key_name(key)

                        if isinstance(key_name, str):
                            if not isinstance(key, Optional):
                                required_keys.append(key_name)
                            expanded_schema[key_name] = _json_schema(
                                sub_schema, is_main_schema=False, description=_get_key_description(key)
                            )
                        elif isinstance(key_name, Or):
                            # JSON schema does not support having a key named one name or another, so we just add both options
                            # This is less strict because we cannot enforce that one or the other is required

                            for or_key in key_name.args:
                                expanded_schema[_get_key_name(or_key)] = _json_schema(
                                    sub_schema, is_main_schema=False, description=_get_key_description(or_key)
                                )

                    return_schema.update(
                        {
                            "type": "object",
                            "properties": expanded_schema,
                            "required": required_keys,
                            "additionalProperties": i,
                        }
                    )

                if is_main_schema:
                    return_schema.update({"$id": schema_id, "$schema": "http://json-schema.org/draft-07/schema#"})
                    if self._name:
                        return_schema["title"] = self._name

                    if definitions_by_name:
                        return_schema["definitions"] = {}
                        for definition_name, definition in definitions_by_name.items():
                            return_schema["definitions"][definition_name] = definition

                if schema.description:
                    return_schema["description"] = self.description

            return _create_or_use_ref(return_schema)

        return _json_schema(self, True)


class Optional(Schema):
    """Marker for an optional part of the validation Schema."""

    _MARKER = object()

    def __init__(self, *args, **kwargs):
        default = kwargs.pop("default", self._MARKER)
        super(Optional, self).__init__(*args, **kwargs)
        if default is not self._MARKER:
            # See if I can come up with a static key to use for myself:
            if _priority(self._schema) != COMPARABLE:
                raise TypeError(
                    "Optional keys with defaults must have simple, "
                    "predictable values, like literal strings or ints. "
                    '"%r" is too complex.' % (self._schema,)
                )
            self.default = default
            self.key = str(self._schema)

    def __hash__(self):
        return hash(self._schema)

    def __eq__(self, other):
        return (
            self.__class__ is other.__class__
            and getattr(self, "default", self._MARKER) == getattr(other, "default", self._MARKER)
            and self._schema == other._schema
        )

    def reset(self):
        if hasattr(self._schema, "reset"):
            self._schema.reset()


class Hook(Schema):
    def __init__(self, *args, **kwargs):
        self.handler = kwargs.pop("handler", lambda *args: None)
        super(Hook, self).__init__(*args, **kwargs)
        self.key = self._schema


class Forbidden(Hook):
    def __init__(self, *args, **kwargs):
        kwargs["handler"] = self._default_function
        super(Forbidden, self).__init__(*args, **kwargs)

    @staticmethod
    def _default_function(nkey, data, error):
        raise SchemaForbiddenKeyError("Forbidden key encountered: %r in %r" % (nkey, data), error)


class Literal(object):
    def __init__(self, value, description=None):
        self._schema = value
        self._description = description

    def __str__(self):
        return self._schema

    def __repr__(self):
        return 'Literal("' + self.schema + '", description="' + (self.description or "") + '")'

    @property
    def description(self):
        return self._description

    @property
    def schema(self):
        return self._schema


class Const(Schema):
    def validate(self, data):
        super(Const, self).validate(data)
        return data


def _plural_s(sized):
    return "s" if len(sized) > 1 else ""

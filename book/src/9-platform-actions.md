# Platform Actions

In this section, we discuss *actions*, which are application-layer messages
that convey changes in group state. Actions are similar to *events* in
[Matrix](https://spec.matrix.org/latest/) and can be used to convey messages
sent within groups as well as changes to persistent state such as
the name or topic of a community or group. Actions are tied to the fundamental
affordances provided by the application. We provide a `CustomAction` that
enables developers to arbitrarily extend the set of existing actions without
having to modify our toolkit. The action types also form the foundation of
our role-based access control system.

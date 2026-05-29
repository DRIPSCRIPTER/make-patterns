# pattern maker promax

IDA Pro plugin that generates byte patterns with wildcards from addresses

## what it does

it takes a list of `rebase()` declarations finds each address in the binary and tries to build a unique byte pattern for it saves the results to `~/Downloads/makepatterns.log`
For functions it tries to pattern from the function start if thats not unique enough it walks xrefs and grabs surrounding instructions instead for data addresses it patterns from a call site

## usage

Right click in the disassembly view and select **pattern maker promax** from the context menu. Paste your rebase declarations in the dialog press OK

format:

```
SomeFunction = rebase(0x1A2B3C)
AnotherThing = rebase(0x4D5E6F)
```

or u can do:

```
const uintptr_t print = rebase(0x9999999);
...
```

output goes to the console and `~/Downloads/makepatterns.log`.

## pro installation

drop the makepatterns.py file into your ida plugins folder

made by nbeater678
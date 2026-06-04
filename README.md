# VanHooks

<p align="center">
</p>

<h3 align="center">
If a function can execute, VanHooks should be able to reach it.
</h3>

<p align="center">
A modern cross-platform hooking and instrumentation framework for reverse engineering, runtime analysis, systems research, and game engine development.
</p>

---

## What is VanHooks?

VanHooks is a next-generation framework for intercepting, observing, and modifying native software at runtime.

Built from the perspective of reverse engineers, engine researchers, and systems developers, VanHooks combines a unified API with support for multiple hooking techniques, architectures, and operating systems.

Whether you're reverse engineering a legacy game engine, building runtime analysis tools, instrumenting native applications, or researching low-level system behavior, VanHooks is designed to provide a single ecosystem for the job.

---

## Independent Architecture

VanHooks is not a fork of SafetyHook, MinHook, PolyHook2, Microsoft Detours, or any other hooking library.

The framework is being developed as an independent implementation with its own:

- API design
- Hook management model
- Cross-platform architecture
- Relocation systems
- Instrumentation workflows
- Long-term roadmap

While VanHooks draws inspiration from decades of work across the reverse engineering community, its goal is not to replicate existing projects—it is to provide a unified platform that scales from simple hooks to large-scale instrumentation projects.

---

## Why VanHooks?

Most hooking libraries specialize in a single area.

- Some focus primarily on inline hooks.
- Some target a single operating system.
- Some expose powerful functionality through multiple disconnected APIs.
- Some were never designed for modern ARM64 environments.

VanHooks is built around a different idea:

> One framework. One mental model. Every hook type.

---

## Features

### Hook Types

- Inline Hooks
- Trampoline Hooks
- Mid-Function Hooks
- VTable Hooks
- Import Address Table (IAT) Hooks
- Export Address Table (EAT) Hooks
- PLT/GOT Hooks
- Runtime Hook Chaining
- Managed Hook Groups
- Unified Hook Lifecycle Management

### Platform Support

| Platform | Status |
|-----------|----------|
| Windows x86 | Supported |
| Windows x64 | Supported |
| Windows ARM64 | Supported |
| Linux x64 | Supported |
| Linux ARM64 | Supported |
| macOS Intel | Supported |
| macOS Apple Silicon | Supported |

### Architecture Support

- x86
- x64
- ARM64

---

## Simple By Default

```cpp
auto hook = vh::hook(target, detour);

hook.enable();
```

Advanced workflows remain available through the same ecosystem.

```cpp
auto hook = vh::vtable(object, index)
    .detour(myDetour)
    .enable();
```

A beginner should be able to install a hook quickly.

An expert should be able to instrument an entire application without leaving the framework.

---

## Ecosystem Positioning

VanHooks exists alongside several excellent projects.

### SafetyHook

SafetyHook focuses on safe and modern inline hooking.

VanHooks shares an emphasis on usability while extending into broader runtime instrumentation and cross-platform workflows.

### MinHook

MinHook remains one of the most respected lightweight Windows hooking libraries.

VanHooks expands beyond this scope with multi-platform and multi-architecture support.

### PolyHook2

PolyHook2 provides a rich collection of advanced hooking techniques.

VanHooks pursues a unified framework approach where different hook types and platforms share a consistent developer experience.

### Microsoft Detours

Microsoft Detours helped define modern API interception.

VanHooks builds upon the broader instrumentation tradition while targeting modern C++ development, ARM64 platforms, and reverse-engineering workflows.

---

## Built For

- Reverse Engineering
- Game Modding
- Runtime Instrumentation
- Binary Analysis
- Engine Research
- Performance Profiling
- Security Research
- Systems Development

---

## Philosophy

### Understand First

Software should be observable.

### Modify Second

Hooking should be reliable, predictable, and maintainable.

### Never Lose Control

Abstractions should simplify workflows without hiding critical details.

---

## Vision

To build one of the most capable and approachable instrumentation frameworks available for modern native software.

Not simply another hooking library.

A platform for understanding software.

---

## TeamVanilla

Created and maintained by TeamVanilla.

Building tools for people who want to understand how software really works.

---

**If a function can execute, VanHooks should be able to reach it.**

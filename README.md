# LocalCam

LocalCam is a Windows desktop application focused on discovering and connecting to Tapo security cameras on a local network.

## Project Status

This project is currently in active development and is not yet production-ready. Features, behavior, and interfaces may change as implementation progresses.

## Tech Stack

- C# (.NET 10, `net10.0-windows`)
- WPF (XAML) for the desktop UI
- .NET networking APIs (`System.Net`, `System.Net.NetworkInformation`) for LAN camera discovery
- GitHub for source control and collaboration

## Current Scope

- Local network scanning for likely Tapo camera devices
- Basic detection results UI in WPF

## Planned Scope

- Stream playback from detected cameras
- Camera selection and connection workflow
- Improved diagnostics and reliability

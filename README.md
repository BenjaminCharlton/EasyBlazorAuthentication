# SimpleBlazorAuthentication

**SimpleBlazorAuthentication** provides really quick, simple and secure authentication for Blazor Server and Blazor WebAssembly applications using ASP .NET Core Identity, HTTP-only cookies and JWTs with rotational refresh.
It's not designed to be infinitely rich in options and configurability (it has enough). It's designed to make securing your Blazor app feel effortless.
Sure, maybe one day you'll have some requirement that isn't supported and you'll need to go back to the hard way.
One day. Maybe. But right now, you have everything you need - right here.

- ASP .NET Core Web APIs (Controllers, or Minimal API endpoints)
- Hosted Blazor web applications
- Stand-alone Blazor web applications
- Microsoft Identity
- CORS configuration
- Token expiry and rotation

It's an authentication starter kit *not* an authorization system. But don't worry - authorization is easy to add on top, and this README will show you how.

## The problem

Setting up authentication has been painful for as long as I've been programming - about 25 years.

Microsoft made things easier in 2016 with templates that included individual user accounts using ASP.NET Core Identity.
But even now (mid-2025), those templates don't wire up a client-side app, a web API, and a token-issuing authority (like a server-hosted Blazor app) together with CORS and sample API calls and stuff.

You still need to connect Identity, JWTs, refresh tokens, CORS, antiforgery protection, cookie handling, and client-side auth state management manually. And that takes hours, sometimes days.

If you're not an expert, it's genuinely daunting. Debugging it always felt like I was groping around in the dark.

Couldn't they just give us something out of the box? They've always said, *There's no one-size-fits-all solution. Security varies from one scenario to another. We couldn't possibly make a template that fits everyone's needs.*

To that I say: *poppycock*. **SimpleBlazorAuthentication** doesn't pretend to be a one-size-fits-all solution.
It's one-size-that-fits-you-at-the-beginning-of-your-project-and-might-even-fit-forever.

## Plays nicely with Aspire - but not tied to it

I now use [.NET Aspire](https://devblogs.microsoft.com/dotnet/introducing-aspire/) on all my projects.
I developed another library - [Aspire4Wasm](https://github.com/BenjaminCharlton/Aspire4Wasm) - to make Aspire easy to use with hosted and stand-alone Blazor WebAssembly projects.
**Aspire4Wasm** provides service discovery and `HttpClient` configuration for Blazor in .NET Aspire distributed applications.
There is a sample showing how **SimpleBlazorAuthentication** and **Aspire4Wasm** work well together, but **SimpleBlazorAuthentication** is completely decoupled and works fine by itself. 

## Quickstart

### Option 1: **Standalone Blazor WebAssembly + Web API**

#### In the Blazor WebAssembly project

#### In the Web API project

### Option 2: **Hosted Blazor WebAssembly + Web API**

#### In the Blazor Server/Host project

#### In the Blazor WebAssembly project

#### In the Web API project

### Option 3: **Blazor Server + Web API**

#### In the Blazor Server project

#### In the Blazor WebAssembly project

#### In the Web API project

### Option 4: **Aspire + Hosted Blazor WebAssembly + Web API**

#### In the Blazor Server project

#### In the Blazor WebAssembly project

#### In the Web API project

## Advanced Configuration

### Introducing Authorization

As stated earlier, **SimpleBlazorAuthentication** is an authentication starter kit *not* an authorization system. But don't worry - authorization is easy to add.

1. Make sure you call the overload of `j` with roles, specifying a type of role. The simplest type is just `IdentityRole`.
1. 

### Passing more user information between the Blazor host and Blazor client

### Using a different login page

## Contributing
The goal is making application security quick and easy for a new project, not creating a fully-featured system like another Duende Identity Server.
This is a hobby project. I welcome improvements that reduce friction. If you spot a bug or want to add a feature, I'd love your help - just open a pull request.
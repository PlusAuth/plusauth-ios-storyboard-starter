
<div align="center">
  <a href="https://plusauth.com/">
    <img src="https://docs.plusauth.com/favicon.png" alt="Logo" width="144">
  </a>
</div>

<h1 align="center">PlusAuth iOS Storyboard Starter Project</h1>

 <p align="center">
    Simple iOS Storyboard XCode project demonstrates basic authentication flows with PlusAuth
    <br />
    <br />
    <a href="https://docs.plusauth.com/quickStart/native/ios/storyboard" target="_blank"><strong>Explore the PlusAuth iOS Storyboard docs »</strong></a>
</p>

<details>
  <summary>Table of Contents</summary>
    <li><a href="#about-the-project">About The Project</a></li>
    <li><a href="#prerequisites">Prerequisites</a></li>
    <li><a href="#getting-started">Getting Started</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#what-is-plusauth">What is PlusAuth</a></li>
 </ol>
</details>

---

## About The Project

It is a very simple iOS Storyboard XCode project demonstrating basic authentication flows such as register, login, and logout. To keep things simple, we used [AppAuth for iOS](https://openid.github.io/AppAuth-iOS/) for authentication.

## Prerequisites

Before running the project, you must first follow these steps:

1. Create a PlusAuth account and a tenant at [PlusAuth Dashboard](https://dashboard.plusauth.com)
2. Navigate to [Clients](https://dashboard.plusauth.com/~clients) tab and create a client of type `Native Application`
3. Go to the details page of the client that you've just created and set the following fields as:

- Redirect Uris:  `com.plusauth.iosexample.plusauth-ios-starter:/oauth2redirect/ios-provider`
- Post Logout Redirect Uris:  `com.plusauth.iosexample.plusauth-ios-starter:/oauth2redirect/ios-provider`

Finally, note your Client Id and domain(e.g., https://example.plusauth.com) for app configuration on the next step.

## Getting Started

First, we need to supply the required configuration values for the application. Rename `PlusAuth.example.plist` file, under the `plusauth-ios-starter` folder, as `PlusAuth.plist`.

Then modify the values inside `PlusAuth.plist` file using your Client ID and your PlusAuth tenant name.

**NOTE:** This poject uses Swift Package Manager as dependency manager.

That's all! Hit the 'Run' button in XCode to start the app.

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.

## What is PlusAuth

PlusAuth helps individuals, teams, and organizations to implement authorization and authentication systems in a secure, flexible and easy way.

<a href="https://plusauth.com/" target="_blank"><strong>Explore the PlusAuth Website »</strong></a>

<a href="https://docs.plusauth.com/" target="_blank"><strong>Explore the PlusAuth Docs »</strong></a>

<a href="https://forum.plusauth.com/" target="_blank"><strong>Explore the PlusAuth Forum »</strong></a>


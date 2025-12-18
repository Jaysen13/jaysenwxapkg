# Extension Template Project

This project was created by PortSwigger to help you quickly start developing extensions in Java.

## Contents
* [Before you start](#before-you-start)
* [Writing your extension](#writing-your-extension)
* [Building your extension](#building-your-extension)
* [Loading the JAR file into Burp](#loading-the-jar-file-into-burp)
* [Sharing your extension](#sharing-your-extension)


## Before you start

Before you begin development, make sure that your project's JDK is set to version "21".


## Writing your extension

To begin development, open the [Extension.java](src/main/java/JaySenExtension.java) file. It includes an example of setting your extension's name, which you can customize with your own logic.

The template contains the following components for building your extension:

* The `initialize` method. This is the entry point for your extension. It is called when the extension is loaded and receives a [montoyaApi](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html) argument, which provides access to all Montoya API features.
* The `Extension` class. This implements the BurpExtension interface, so your extension is recognized and loaded by Burp.

For more information on Montoya API features, see the [JavaDoc](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html).

To explore example extensions, visit our [GitHub repository](https://github.com/PortSwigger/burp-extensions-montoya-api-examples).

For more information on creating extensions, see our [documentation](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating).

If you have any questions or need help from the community, join our [Discord channel](https://discord.com/channels/1159124119074381945/1164175825474686996).


## Building your extension

When you're ready to test and use your extension, follow these steps to build a JAR file and load it into Burp.

### Building the JAR file

To build the JAR file, run the following command in the root directory of this project:

* For UNIX-based systems: `./gradlew jar`
* For Windows systems: `gradlew jar`

If successful, the JAR file is saved to `<project_root_directory>/build/libs/<project_name>.jar`. If the build fails, errors are shown in the console. By default, the project name is `extension-template-project`. You can change this in the [settings.gradle.kts](./settings.gradle.kts) file.


## Loading the JAR file into Burp

To load the JAR file into Burp:

1. In Burp, go to **Extensions > Installed**.
2. Click **Add**.
3. Under **Extension details**, click **Select file**.
4. Select the JAR file you just built, then click **Open**.
5. [Optional] Under **Standard output** and **Standard error**, choose where to save output and error messages.
6. Click **Next**. The extension is loaded into Burp.
7. Review any messages displayed in the **Output** and **Errors** tabs.
8. Click **Close**.

Your extension is loaded and listed in the **Burp extensions** table. You can test its behavior and make changes to the code as necessary.

### Reloading the JAR file in Burp

If you make changes to the code, you must rebuild the JAR file and reload your extension in Burp for the changes to take effect.

To rebuild the JAR file, follow the steps for [building the JAR file](#building-the-jar-file).

To quickly reload your extension in Burp:

1. In Burp, go to **Extensions > Installed**.
2. Hold `Ctrl` or `⌘`, and select the **Loaded** checkbox next to your extension.


## Sharing your extension

Once you've built your extension, we'd love to see what you've created!

Share your extension on our [PortSwigger Discord](https://discord.com/channels/1159124119074381945/1164175825474686996) #extensions channel to get feedback, showcase your work, and connect with other developers.
Then take it to the next level by submitting your extension to the BApp store, making it available to the community of 80,000+ users worldwide.

For guidance on the submission process, see [Submitting extensions to the BApp store](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/bapp-store-submitting-extensions).
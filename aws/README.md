Some manual steps are required for AWS setup since I'm too stupid to use cloudformation correctly:

- Apply cloudformation template
- Create a python lambda ``smileyDayGetEncryptedPasswords`` with role from cloudformation, and upload appropriate zip
	- Also add an API gateway trigger to this lambda
- Create a python lambda ``smileyDayGetSteps`` with role from cloudformation, and upload the other lambda code
	- Add the same API gateway trigger to this lambda

Now that the AWS infrastructure is set up you need to change the API URL in the app.
You can do this by changing the ``api_url`` key in ``strings.xml`` to the URL of your API gateway.
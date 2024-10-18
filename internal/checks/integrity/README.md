Here’s a step-by-step summary of what we’ve done so far to set up malware scanning on your \*\*S3 bucket\*\* using \*\*AWS Lambda\*\*:

\### Step 1: Create a Lambda Function for Malware Scanning

We created a \*\*Lambda function\*\* that will be triggered when files are uploaded to the S3 bucket. The Lambda function will download the file from the S3 bucket, scan it for malware, and log the result.

The Lambda function code uses \*\*ClamAV\*\* for scanning, but in this basic setup, we created a simple Python function that we packaged into a ZIP file and uploaded to \*\*AWS Lambda\*\*.

Here’s how we created the function:

\- Created a Python script (\`lambda\_function.py\`) containing the function code to handle file downloads and scanning.

\- Packaged the code into a ZIP file using:

\`\`\`bash

zip function.zip lambda\_function.py

\`\`\`

\- Created the Lambda function using the \*\*AWS CLI\*\*:

\`\`\`bash

aws lambda create-function \\

\--function-name MalwareScanFunction \\

\--runtime python3.8 \\

\--role arn:aws:iam::682033472444:role/LambdaS3ExecutionRole \\

\--handler lambda\_function.lambda\_handler \\

\--zip-file fileb://function.zip

\`\`\`

\### Step 2: Create an IAM Role for Lambda

We created an \*\*IAM role\*\* that allows Lambda to assume permissions for execution and access to the S3 bucket. This role is necessary because Lambda needs permission to interact with other AWS services like \*\*S3\*\* and \*\*CloudWatch\*\*.

1\. Created an \*\*IAM role\*\* with a trust policy that allows \*\*Lambda\*\* to assume the role:

\`\`\`bash

aws iam create-role --role-name LambdaS3ExecutionRole \\

\--assume-role-policy-document '{

"Version": "2012-10-17",

"Statement": \[

{

"Effect": "Allow",

"Principal": {

"Service": "lambda.amazonaws.com"

},

"Action": "sts:AssumeRole"

}

\]

}'

\`\`\`

2\. Attached the \*\*AWSLambdaBasicExecutionRole\*\* and \*\*AmazonS3ReadOnlyAccess\*\* policies to the role so Lambda can access S3 and write logs:

\`\`\`bash

aws iam attach-role-policy --role-name LambdaS3ExecutionRole \\

\--policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

\`\`\`

\`\`\`bash

aws iam attach-role-policy --role-name LambdaS3ExecutionRole \\

\--policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

\`\`\`

\### Step 3: Set Up S3 Event Notifications to Trigger Lambda

Next, we configured the \*\*S3 bucket\*\* (\`my-cui-bucket\`) to trigger the Lambda function whenever a new object is uploaded.

\- We attempted to set up the bucket notification:

\`\`\`bash

aws s3api put-bucket-notification-configuration --bucket my-cui-bucket --notification-configuration '{

"LambdaFunctionConfigurations": \[

{

"LambdaFunctionArn": "arn:aws:lambda:us-east-1:682033472444:function:MalwareScanFunction",

"Events": \["s3:ObjectCreated:\*"\]

}

\]

}'

\`\`\`

\### Step 4: Add Permissions for S3 to Invoke Lambda

We encountered an error because \*\*S3\*\* did not have permission to invoke the \*\*Lambda function\*\*. To resolve this, we added an \*\*InvokeFunction\*\* permission to the Lambda function, allowing S3 to trigger it.

We granted \*\*S3\*\* permission to invoke the Lambda function with the following command:

\`\`\`bash

aws lambda add-permission \\

\--function-name MalwareScanFunction \\

\--principal s3.amazonaws.com \\

\--statement-id s3invoke \\

\--action "lambda:InvokeFunction" \\

\--source-arn arn:aws:s3:::my-cui-bucket \\

\--source-account 682033472444

\`\`\`

\### Step 5: Retry Setting Up the S3 Bucket Notification

After granting the necessary permissions, we re-ran the command to link the \*\*S3 bucket\*\* to the \*\*Lambda function\*\* using S3 event notifications:

\`\`\`bash

aws s3api put-bucket-notification-configuration --bucket my-cui-bucket --notification-configuration '{

"LambdaFunctionConfigurations": \[

{

"LambdaFunctionArn": "arn:aws:lambda:us-east-1:682033472444:function:MalwareScanFunction",

"Events": \["s3:ObjectCreated:\*"\]

}

\]

}'

\`\`\`

This command should now succeed, and the \*\*Lambda function\*\* will be triggered whenever an object is uploaded to \*\*my-cui-bucket\*\*.

\### Step 6: Testing the Setup

Finally, we uploaded a file to \*\*my-cui-bucket\*\* to test whether the Lambda function is triggered and whether it scans the file.

We monitored the logs using \*\*CloudWatch Logs\*\* to confirm that the function was invoked and to see the scan results:

\`\`\`bash

aws logs tail /aws/lambda/MalwareScanFunction --follow

\`\`\`

\### Conclusion

At this point, the \*\*MalwareScanFunction\*\* should be fully set up and integrated with the \*\*S3 bucket\*\*. It will automatically scan any new objects uploaded to the bucket and log the results.
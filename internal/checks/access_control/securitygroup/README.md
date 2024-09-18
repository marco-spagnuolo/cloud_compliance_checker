
\## Come Utilizzare

\### 1. Crea le Policy AWS

Per testare lo strumento, crea alcune policy di esempio su AWS, come indicato di seguito:

\- \*\*Policy per Utenti con Accesso in Sola Lettura\*\*:

\`\`\`json

{

"Version": "2012-10-17",

"Statement": \[

{

"Effect": "Allow",

"Action": \[

"ec2:DescribeInstances",

"ec2:DescribeVolumes",

"s3:ListBucket",

"s3:GetObject"

\],

"Resource": "\*"

}

\]

}

\`\`\`

\- \*\*Policy per Amministratori\*\*:

\`\`\`json

{

"Version": "2012-10-17",

"Statement": \[

{

"Effect": "Allow",

"Action": "\*",

"Resource": "\*"

}

\]

}

\`\`\`

\- \*\*Policy per la Gestione delle Proprie Credenziali IAM\*\*:

\`\`\`json

{

"Version": "2012-10-17",

"Statement": \[

{

"Effect": "Allow",

"Action": \[

"iam:ChangePassword",

"iam:GetUser"

\],

"Resource": "arn:aws:iam::123456789012:user/${aws:username}"

}

\]

}

\`\`\`

\### 2. Definisci i Requisiti Aziendali

Nel codice di \`cloud\_compliance\_checker\`, abbiamo definito un insieme di policy consentite all'interno della funzione \`validatePolicy\`. Questa funzione confronta le policy assegnate agli utenti con l'elenco seguente:

\- \*\*Policy Consentite\*\*:

\- \`ReadOnlyPolicy\`

\- \`AdminPolicy\`

\- \`SelfManageCredentialsPolicy\`

Puoi modificare questo elenco all'interno del file \`iam\_check.go\` per adattarlo ai tuoi requisiti aziendali.


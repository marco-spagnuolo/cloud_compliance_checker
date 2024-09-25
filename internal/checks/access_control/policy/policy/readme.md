
### 1. Crea le Policy AWS

Per testare lo strumento, crea alcune policy di esempio su AWS, come indicato di seguito:

- **Policy per Utenti con Accesso in Sola Lettura**:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "s3:ListBucket",
          "s3:GetObject"
        ],
        "Resource": "*"
      }
    ]
  }
  ```

- **Policy per Amministratori**:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }
    ]
  }
  ```

- **Policy per la Gestione delle Proprie Credenziali IAM**:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "iam:ChangePassword",
          "iam:GetUser"
        ],
        "Resource": "arn:aws:iam::123456789012:user/${aws:username}"
      }
    ]
  }
  ```

### 2. Definisci i Requisiti Aziendali

Nel codice  abbiamo definito un insieme di policy consentite all'interno della funzione `validatePolicy`. Questa funzione confronta le policy assegnate agli utenti con l'elenco seguente:

- **Policy Consentite**:
  - `ReadOnlyPolicy`
  - `AdminPolicy`
  - `SelfManageCredentialsPolicy`

Puoi modificare questo elenco all'interno del file `iam_check.go` per adattarlo ai tuoi requisiti aziendali.

### 3. Esegui il Controllo

Per eseguire il controllo, segui questi passaggi:

1. **Compila ed esegui il programma**:
   ```bash
   go build
   ./cloud_compliance_checker
   ```

   Il programma eseguirà un controllo su tutti gli utenti IAM nel tuo account AWS e verificherà se le policy assegnate sono conformi ai requisiti aziendali. I risultati verranno stampati a schermo.

### 2. Aggiungi o Modifica i Requisiti

Se desideri aggiungere nuovi requisiti aziendali o modificare quelli esistenti, puoi farlo modificando la funzione `validatePolicy`

### 3. Output

Il programma stamperà i risultati della verifica per ciascun utente IAM. Se un utente ha una policy non conforme, verrà segnalata come non conforme:

```bash
Verifica dell'utente: test-user
L'utente test-user ha la policy: ReadOnlyPolicy
Policy ReadOnlyPolicy conforme per l'utente test-user
```

Se un utente ha una policy non consentita, vedrai un messaggio simile a questo:

```bash
Verifica dell'utente: admin-user
L'utente admin-user ha la policy: AdminPolicy
Policy AdminPolicy conforme per l'utente admin-user
```

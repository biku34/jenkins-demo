pipeline {
    agent any

    stages {

        stage('Show Updated Lines') {
            steps {
                bat '''
                echo ===== Changed Files =====
                git diff %GIT_PREVIOUS_COMMIT% %GIT_COMMIT% --name-only

                echo ===== Updated Lines =====
                git diff %GIT_PREVIOUS_COMMIT% %GIT_COMMIT%
                '''
            }
        }

    }
}

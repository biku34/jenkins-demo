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

        stage('SonarQube Scan') {
            steps {
                withSonarQubeEnv('SonarQube1') {
                    bat '''
                    docker run --rm ^
                    -v "%WORKSPACE%:/usr/src" ^
                    sonarsource/sonar-scanner-cli ^
                    -Dsonar.projectKey=jenkins-test ^
                    -Dsonar.sources=. ^
                    -Dsonar.host.url=http://host.docker.internal:9000 ^
                    -Dsonar.login=sqa_0f57545491a3e78045f91b59da831db48f95cc9f
                    '''
                }
            }
        }

    }
}

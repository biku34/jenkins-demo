pipeline {
    agent any

    stages {

        stage('Clone Check') {
            steps {
                echo 'Code successfully cloned from GitHub!'
            }
        }

        stage('List Files') {
            steps {
                bat 'dir'
            }
        }

    }
}

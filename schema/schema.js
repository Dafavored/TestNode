const { buildSchema } = require("graphql");

module.exports = buildSchema(`
    type User {
        id: ID!
        name: String!
        email: String!
        role: String!
    }


    type VitalSign {
        id: ID!
        patientId: ID!
        temperature: Float
        heartRate: Float
        bloodPressure: String
        respiratoryRate: Float
    }

    type MotivationalTip {
        id: ID!
        nurseId: ID!
        tip: String!
    }

    type EmergencyAlert {
        id: ID!
        patientId: ID!
        alertMessage: String!
    }

    input RegisterInput {
        name: String!
        email: String!
        password: String!
        role: String!
    }

    input VitalSignInput {
        patientId: ID!
        temperature: Float
        heartRate: Float
        bloodPressure: String
        respiratoryRate: Float
    }

    type Query {
        getVitalSigns(patientId: ID!): [VitalSign!]
        getMotivationalTips: [MotivationalTip!]
    }

    type Mutation {
        registerUser(input: RegisterInput): User
        login(email: String!, password: String!): String
        addVitalSign(input: VitalSignInput): VitalSign
        addMotivationalTip(tip: String!): MotivationalTip
        sendEmergencyAlert(alertMessage: String!): EmergencyAlert
    }
    type Mutation {
    addVitalSign(input: VitalSignInput): VitalSign
    }
    
`
);

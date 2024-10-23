//
//  FirebasePushNotificationHelper.swift
//  PHPServer
//
//  Created by Vedika on 08/10/24.
//
import Foundation
import SwiftJWT

class FirebasePushNotificationHelper {

    // Load Firebase service account credentials from a JSON file
    func loadServiceAccount(fileName:String) -> FirebaseCredentials? {
        guard let url = Bundle.main.url(forResource: fileName, withExtension: "json") else {
            print("Failed to find .json in bundle.")
            return nil
        }
        do {
            let data = try Data(contentsOf: url)
            let credentials = try JSONDecoder().decode(FirebaseCredentials.self, from: data)
            return credentials
        } catch {
            print("Error reading or decoding JSON file: \(error)")
            return nil
        }
    }

    func loadServiceAccount(fileURL:URL) -> FirebaseCredentials? {
        do {
            let data = try Data(contentsOf: fileURL)
            let credentials = try JSONDecoder().decode(FirebaseCredentials.self, from: data)
            return credentials
        } catch {
            print("Error reading or decoding JSON file: \(error)")
            return nil
        }
    }

    // Convert PEM-formatted private key to Data
    func convertPEMToData(_ pemString: String) -> Data? {
        // Remove the PEM header/footer
        let cleanedKey = pemString
            .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")

        // Decode Base64 string into Data
        return Data(base64Encoded: cleanedKey)
    }

    // Generate JWT using Firebase service account credentials
    func generateJWT(serviceAccount: FirebaseCredentials) -> String? {
        let now = Date()
        let expiration = Date(timeIntervalSinceNow: 3600)

        let claims = MyClaims(
            iss: serviceAccount.clientEmail,
            sub: serviceAccount.clientEmail,
            aud: "https://oauth2.googleapis.com/token",
            iat: now,
            exp: expiration,
            scope: "https://www.googleapis.com/auth/firebase.messaging"
        )

        let privateKeyData = convertPEMToData(serviceAccount.privateKey)
        var jwt = JWT(claims: claims)
        let jwtSigner = JWTSigner.rs256(privateKey: privateKeyData!)

        do {
            let signedJWT = try jwt.sign(using: jwtSigner)
            return signedJWT
        } catch {
            print("Error signing JWT: \(error)")
            return nil
        }
    }

    // Fetch OAuth 2.0 token using the generated JWT
    func fetchOAuthToken(jwt: String, completion: @escaping (String?) -> Void) {
        let url = URL(string: "https://oauth2.googleapis.com/token")!

        var request = URLRequest(url: url)
        request.httpMethod = "POST"

        let bodyParams = [
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt
        ]

        request.httpBody = try? JSONSerialization.data(withJSONObject: bodyParams)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data, error == nil else {
                print("Error fetching token: \(String(describing: error))")
                completion(nil)
                return
            }

            if let tokenResponse = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
               let accessToken = tokenResponse["access_token"] as? String {
                completion(accessToken)
            } else {
                print("Failed to parse token response")
                completion(nil)
            }
        }
        task.resume()
    }

    // Send push notification to a specific topic
    func sendPushNotification(projectId:String ,toTopic topic: String, title: String, body: String, serverToken: String, soundOn: Bool, extraData: [String: Any]) {
        let url = URL(string: "https://fcm.googleapis.com/v1/projects/\(projectId)/messages:send")! //megically
        print("URL: \(url)")

        let notification: [String: Any] = [
            "message": [
                "topic": topic,
                "notification": [
                    "title": title,
                    "body": body
                ],
                "android": [
                    "notification": [
                        "sound": soundOn ? "default" : ""
                    ]
                ],
                "apns": [
                    "payload": [
                        "aps": [
                            "sound": soundOn ? "default" : ""
                        ]
                    ]
                ],
                "data": extraData
            ]
        ]

        let jsonData = try? JSONSerialization.data(withJSONObject: notification)

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(serverToken)", forHTTPHeaderField: "Authorization")

        request.httpBody = jsonData

        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                print("Error sending push notification: \(error)")
                return
            }

            if let httpResponse = response as? HTTPURLResponse {
                if httpResponse.statusCode == 200 {
                    print("Push notification sent successfully to topic \(topic)")
                } else {
                    print("Failed to send push notification, status code: \(httpResponse.statusCode)")
                }
            }

            // Print the response data as string or JSON
            if let data = data {
                if let responseString = String(data: data, encoding: .utf8) {
                    print("Response data: \(responseString)")
                }

                // Optionally, try to convert it to JSON
                do {
                    let jsonResponse = try JSONSerialization.jsonObject(with: data, options: [])
                    print("JSON response: \(jsonResponse)")
                } catch {
                    print("Failed to parse JSON response: \(error)")
                }
            }
        }

        task.resume()
    }
}

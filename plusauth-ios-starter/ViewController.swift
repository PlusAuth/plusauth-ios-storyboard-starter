import UIKit
import AppAuth

// PlusAuth.plist properties objects
struct PlusAuth : Decodable {
    let clientId, issuer : String
}

struct Root : Decodable {
    let credentials : PlusAuth
}

private var plusAuthCredentials = PlusAuth(clientId: "", issuer: "")
private let redirectUrl: String = "\(Bundle.main.bundleIdentifier ?? ""):/oauth2redirect/ios-provider";

private var config: OIDServiceConfiguration?
// State variables to store user auth state
private let plusAuthStateKey: String = "plusAuthState";
private let storageSuitName = "com.plusauth.iosexample"

class ViewController: UIViewController {
    
    @IBOutlet weak var profileTextView: UITextView!
    @IBOutlet weak var usernameTextView: UITextView!
    @IBOutlet weak var loginButton: UIButton!
    @IBOutlet weak var logoutButton: UIButton!
    
    private var authState: OIDAuthState?
    private var isLoggedIn: Bool = false
    private var userInfoJson: [AnyHashable: Any]?

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        self.readCredentials()
        self.discoverConfiguration()
        self.loadState()
    }
}

//MARK: IBActions
extension ViewController {
    @IBAction func onLoginButtonClick(_ sender: Any) {
        self.login()
    }
    
    @IBAction func onLogoutButtonClick(_ sender: Any) {
        self.logout()
    }
}

//MARK: PlusAuth Methods
extension ViewController {
    func discoverConfiguration() {
        guard let issuerUrl = URL(string: plusAuthCredentials.issuer) else {
          print("Error creating URL for : \(plusAuthCredentials.issuer)")
          return
        }
        
        // Get PlusAuth auth endpoints
        OIDAuthorizationService.discoverConfiguration(forIssuer: issuerUrl) { configuration, error in
           if(error != nil) {
               print("Error: \(error?.localizedDescription ?? "DEFAULT_ERROR")")
           } else {
               config = configuration
           }
        }
    }
    
    func login() {
        // Create redirectURI from redirectURL string
        guard let redirectURI = URL(string: redirectUrl) else {
            print("Error creating URL for : \(redirectUrl)")
            return
        }
        
        guard let appDelegate = UIApplication.shared.delegate as? AppDelegate else {
            print("Error accessing AppDelegate")
            return
        }

        // Create login request
        let request = OIDAuthorizationRequest(configuration: config!, clientId: plusAuthCredentials.clientId, clientSecret: nil, scopes: ["openid", "profile", "offline_access"],
                                        redirectURL: redirectURI, responseType: OIDResponseTypeCode, additionalParameters: nil)
        // performs authentication request
        appDelegate.currentAuthorizationFlow = OIDAuthState.authState(byPresenting: request, presenting: self) { (authState, error) in
            if let authState = authState {
                self.setAuthState(state: authState)
                self.fetchUserInfo()
            } else {
                print("Authorization error: \(error?.localizedDescription ?? "DEFAULT_ERROR")")
            }
        }
    }
    
    func logout() {
        // Create redirectURI from redirectURL string
        guard let redirectURI = URL(string: redirectUrl) else {
           print("Error creating URL for : \(redirectUrl)")
           return
        }
        
        guard let appDelegate = UIApplication.shared.delegate as? AppDelegate else {
            print("Error accessing AppDelegate")
            return
        }
       
        guard let idToken = authState?.lastTokenResponse?.idToken else { return }
        // Create logout request
        let request = OIDEndSessionRequest(configuration: config!, idTokenHint: idToken, postLogoutRedirectURL: redirectURI, additionalParameters: nil)
        guard let userAgent = OIDExternalUserAgentIOS(presenting: self) else { return }

        // performs logout request
        appDelegate.currentAuthorizationFlow = OIDAuthorizationService.present(request, externalUserAgent: userAgent, callback: { (_, error) in
           self.setAuthState(state: nil)
        })
    }
    
    // Get authenticaed user info from PlusAuth
    func fetchUserInfo() {
        guard let userinfoEndpoint = authState?.lastAuthorizationResponse.request.configuration.discoveryDocument?.userinfoEndpoint else {
            print("Userinfo endpoint not declared in discovery document")
            return
        }
        
        let currentAccessToken: String? = authState?.lastTokenResponse?.accessToken

        authState?.performAction() { (accessToken, idToken, error) in

            if error != nil  {
                print("Error fetching fresh tokens: \(error?.localizedDescription ?? "ERROR")")
                return
            }
            guard let accessToken = accessToken else {
                print("Error getting accessToken")
                return
            }

            if currentAccessToken != accessToken {
                print("Access token was refreshed automatically (\(currentAccessToken ?? "CURRENT_ACCESS_TOKEN") to \(accessToken))")
            } else {
                print("Access token was fresh and not updated \(accessToken)")
            }

            var urlRequest = URLRequest(url: userinfoEndpoint)
            urlRequest.allHTTPHeaderFields = ["Authorization":"Bearer \(accessToken)"]

            let task = URLSession.shared.dataTask(with: urlRequest) { data, response, error in

                DispatchQueue.main.async {
                    
                    guard error == nil else {
                        print("HTTP request failed \(error?.localizedDescription ?? "ERROR")")
                        return
                    }
                    guard let response = response as? HTTPURLResponse else {
                        print("Non-HTTP response")
                        return
                    }
                    guard let data = data else {
                        print("HTTP response data is empty")
                        return
                    }

                    var json: [AnyHashable: Any]?

                    do {
                        json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
                    } catch {
                        print("JSON Serialization Error")
                    }

                    if response.statusCode != 200 {
                        let responseText: String? = String(data: data, encoding: String.Encoding.utf8)

                        if response.statusCode == 401 {
                            let oauthError = OIDErrorUtilities.resourceServerAuthorizationError(withCode: 0,
                                                                                                errorResponse: json,
                                                                                                underlyingError: error)
                            self.authState?.update(withAuthorizationError: oauthError)
                            print("Authorization Error (\(oauthError)). Response: \(responseText ?? "RESPONSE_TEXT")")
                        } else {
                            print("HTTP: \(response.statusCode), Response: \(responseText ?? "RESPONSE_TEXT")")
                        }
                        return
                    }
                    self.userInfoJson = json
                    self.updateUI()
                }
            }
            task.resume()
        }
    }
}

//MARK: Helper Methods
extension ViewController {
    
    // Read clientId and issuer from PlusAuth.plist file
    func readCredentials(){
        let url = Bundle.main.url(forResource: "PlusAuth", withExtension:"plist")!
        do {
            let data = try Data(contentsOf: url)
            let result = try PropertyListDecoder().decode(Root.self, from: data)
            plusAuthCredentials = result.credentials
        } catch {
            print(error)
        }
    }
    
    // Save user state to local
    func saveState() {
        guard let data = try? NSKeyedArchiver.archivedData(withRootObject: self.authState as Any, requiringSecureCoding: true) else {
            return
        }
        
        if let userDefaults = UserDefaults(suiteName: storageSuitName) {
            userDefaults.set(data, forKey: plusAuthStateKey)
            userDefaults.synchronize()
        }
   }

    // Load local state info if exists
   func loadState() {
       guard let data = UserDefaults(suiteName: storageSuitName)?.object(forKey: plusAuthStateKey) as? Data else {
          return
      }
      do {
          let authState = try NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(data) as? OIDAuthState
          self.setAuthState(state: authState)
          // Fetch user info if user authenticated
          self.fetchUserInfo()
     } catch {
         print(error)
     }
   }
    
    // Set user auth state
    func setAuthState(state: OIDAuthState?) {
        if (self.authState == state) {
            return;
        }
        self.authState = state;
        self.isLoggedIn = state?.isAuthorized == true
        self.stateChanged()
    }
    
    func updateUI() {
        if(self.isLoggedIn) {
            self.loginButton.isHidden = true
            self.logoutButton.isHidden = false
            if(userInfoJson != nil) {
                if let json = self.userInfoJson {
                    self.usernameTextView.text = "Username: \(json["username"] ?? "-")"
                    var profileInfo = ""
                    for (key, value) in json {
                        profileInfo += "\(key): \(value is NSNull ? "-" : value), "
                    }
                    self.profileTextView.text = profileInfo
                }
            }
        } else {
            self.logoutButton.isHidden = true
            self.loginButton.isHidden = false
            self.usernameTextView.text = "Username: -"
            self.profileTextView.text = "-"
        }
    }
    
    func stateChanged() {
        self.saveState()
        self.updateUI()
    }

}

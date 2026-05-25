import json
import jwt
import os
import time
import traceback
from datetime import datetime

from flask import Flask, request, jsonify
from flask_cors import CORS

# Import the production VFoldProtocol class from the local directory
from VFoldProtocol import VFoldProtocol 

app = Flask(__name__)
# Enable flexible CORS for modular API gateway microservice patterns
# !! EDIT ORIGINS FOR YOUR SPECIFIC DOMAIN(S) !!
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

def resolve_secret(env_var_name):
    """
    Platform-agnostic configuration resolver. Defaults to standard system 
    environment variables. For advanced enterprise setups, developers can wrap 
    this interface with cloud-native secrets management tools (e.g., AWS Secrets 
    Manager, HashiCorp Vault, or GCP Secret Manager).
    """
    secret = os.environ.get(env_var_name)
    if not secret:
        raise ValueError(f"Required configuration environment variable missing: {env_var_name}")
    return secret

@app.route('/validate-token', methods=['POST'])
def validate_token():
    logger_name = "TokenValidatorEngine"

    try:
        print(f"🚀 Starting token validation execution envelope...")

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Malformed request', 'message': 'Missing JSON payload'}), 400

        token = data.get('token')
        if not token:
            return jsonify({'error': 'Token required'}), 400

        print(f"🔐 Extracting system context configurations...")

        # Resolve validation configurations fluidly from the runtime context environment
        try:
            signing_key = resolve_secret("VAULT_SIGNING_KEY")
            sovereign_string = resolve_secret("SOVEREIGN_CONTEXT_STRING")
        except ValueError as cfg_err:
            print(f"❌ Configuration Error: {str(cfg_err)}")
            return jsonify({'error': 'SERVER_CONFIG_ERROR', 'message': 'Validator is missing secure context.'}), 500

        # Instantiate the VFold engine using the resolved context parameter
        protocol = VFoldProtocol(sovereign_string)

        print(f"🔐 Executing token signature and claims verification...")

        # Execute cryptographic signature validation and claims verification
        try:
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=['HS256'],
                audience='sds-vault-access',
                issuer='sds-vault-system',
                leeway=30
            )

            # Core sovereign isolation: Extract identity and fold it instantly at the system boundary
            email_to_fold = payload.get('email')
            if not email_to_fold:
                return jsonify({'error': 'Invalid payload', 'message': 'Token missing identity claim'}), 400
                
            folded_id = protocol.fold(email_to_fold)

            print(f"✅ Token verified successfully. Identity mapped to unique Folded ID.")

            return jsonify({
                'valid': True,
                'folded_id': folded_id,  # Return the anonymized topological handle down-stack
                'mode': payload.get('mode'),
                'expires_at': payload.get('exp'),
                'issued_at': payload.get('iat')
            }), 200

        except jwt.ExpiredSignatureError:
            print(f"⏰ Token validation rejected: Ephemeral credential signature has expired.")
            return jsonify({'valid': False, 'error': 'Token expired'}), 401

        except jwt.InvalidTokenError as sig_err:
            print(f"🚫 Security Warning: Authentication rejection due to invalid token -> {str(sig_err)}")
            return jsonify({'valid': False, 'error': 'Invalid token'}), 401

    except Exception as e:
        error_msg = traceback.format_exc()
        # Keep detailed system stack traces tucked safely inside local container logs
        print(f"❌ [{logger_name}] Critical Exception: {str(e)}")
        print(f"📋 Stack trace:\n{error_msg}")

        # Obfuscate interior error dynamics from external clients to prevent environment mapping
        return jsonify({
            'error': 'VALIDATION_SYSTEM_FAILURE',
            'message': 'An unexpected processing failure occurred within the validator service boundary.'
        }), 500

if __name__ == "__main__":
    # Standard fallback configuration for local container execution or cloud native orchestration
    bind_port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=bind_port)

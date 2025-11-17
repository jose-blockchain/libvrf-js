// Licensed under the MIT license.

import { VRFType } from './types';

/**
 * Abstract base class representing a VRF object associated with a specific VRF type.
 */
export abstract class VRFObject {
  protected type: VRFType = VRFType.UNKNOWN;

  /**
   * Checks whether this object is properly initialized.
   */
  abstract isInitialized(): boolean;

  /**
   * Returns the VRF type associated with this object.
   */
  getType(): VRFType {
    return this.type;
  }

  /**
   * Sets the VRF type for this object.
   */
  protected setType(type: VRFType): void {
    this.type = type;
  }
}

/**
 * Interface for clonable objects
 */
export interface Clonable<T> {
  /**
   * Creates a deep copy of this object.
   */
  clone(): T;
}

/**
 * Interface for serializable objects
 */
export interface Serializable {
  /**
   * Serializes the object into a Uint8Array.
   */
  toBytes(): Uint8Array;

  /**
   * Deserializes an object from a Uint8Array for the specified VRF type.
   * Returns true if deserialization was successful.
   */
  fromBytes(type: VRFType, data: Uint8Array): boolean;
}

/**
 * Abstract base class representing a VRF proof object.
 */
export abstract class Proof extends VRFObject implements Clonable<Proof>, Serializable {
  /**
   * Returns the VRF value associated with this proof.
   */
  abstract getVRFValue(): Uint8Array;

  /**
   * Creates a deep copy of this proof.
   */
  abstract clone(): Proof;

  /**
   * Serializes the proof into a Uint8Array.
   */
  abstract toBytes(): Uint8Array;

  /**
   * Deserializes a proof from a Uint8Array.
   */
  abstract fromBytes(type: VRFType, data: Uint8Array): boolean;
}

/**
 * Abstract base class representing a VRF public key object.
 */
export abstract class PublicKey extends VRFObject implements Clonable<PublicKey>, Serializable {
  /**
   * Verifies the given VRF proof against the provided input data.
   * Returns a tuple [success, vrfValue] where success indicates if verification passed.
   */
  abstract verifyVRFProof(input: Uint8Array, proof: Proof): [boolean, Uint8Array];

  /**
   * Creates a deep copy of this public key.
   */
  abstract clone(): PublicKey;

  /**
   * Serializes the public key into a Uint8Array (DER-encoded SPKI).
   */
  abstract toBytes(): Uint8Array;

  /**
   * Deserializes a public key from a Uint8Array.
   */
  abstract fromBytes(type: VRFType, data: Uint8Array): boolean;
}

/**
 * Abstract base class representing a VRF secret key object.
 */
export abstract class SecretKey extends VRFObject implements Clonable<SecretKey> {
  /**
   * Generates a VRF proof for the given input data using this secret key.
   */
  abstract getVRFProof(input: Uint8Array): Proof | null;

  /**
   * Returns the public key corresponding to this secret key.
   */
  abstract getPublicKey(): PublicKey | null;

  /**
   * Creates a deep copy of this secret key.
   */
  abstract clone(): SecretKey;
}


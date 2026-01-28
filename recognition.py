from __future__ import annotations
import numpy as np
import cv2
import face_recognition
from dataclasses import dataclass
from typing import Optional, Tuple

@dataclass
class FaceResult:
    embedding: np.ndarray
    face_count: int
    quality_ok: bool
    quality_reason: Optional[str]

def _decode_image_bytes(image_bytes: bytes) -> Tuple[np.ndarray, np.ndarray]:
    data = np.frombuffer(image_bytes, dtype=np.uint8)
    bgr = cv2.imdecode(data, cv2.IMREAD_COLOR)
    if bgr is None:
        raise ValueError("Invalid image bytes (decode failed).")
    rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)
    return bgr, rgb

def _quality_gate(bgr: np.ndarray) -> Tuple[bool, Optional[str]]:
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)

    # Blur: variance of Laplacian (lower = blurrier)
    blur_score = cv2.Laplacian(gray, cv2.CV_64F).var()
    if blur_score < 45:
        return False, f"image_too_blurry(blur={blur_score:.1f})"

    # Brightness: mean pixel value (too low = dark, too high = blown out)
    brightness = float(np.mean(gray))
    if brightness < 40:
        return False, f"image_too_dark(brightness={brightness:.1f})"
    if brightness > 220:
        return False, f"image_too_bright(brightness={brightness:.1f})"

    return True, None

def extract_embedding(image_bytes: bytes) -> FaceResult:
    bgr, rgb = _decode_image_bytes(image_bytes)

    quality_ok, quality_reason = _quality_gate(bgr)
    if not quality_ok:
        return FaceResult(embedding=np.array([]), face_count=0, quality_ok=False, quality_reason=quality_reason)

    locations = face_recognition.face_locations(rgb, model="hog")
    encodings = face_recognition.face_encodings(rgb, known_face_locations=locations)

    if len(encodings) == 0:
        return FaceResult(embedding=np.array([]), face_count=0, quality_ok=True, quality_reason=None)

    if len(encodings) != 1:
        return FaceResult(embedding=np.array([]), face_count=len(encodings), quality_ok=True, quality_reason=None)

    return FaceResult(embedding=encodings[0], face_count=1, quality_ok=True, quality_reason=None)

def cosine_distance(a: np.ndarray, b: np.ndarray) -> float:
    a = a.astype(np.float64)
    b = b.astype(np.float64)
    denom = (np.linalg.norm(a) * np.linalg.norm(b))
    if denom == 0:
        return 1.0
    return 1.0 - float(np.dot(a, b) / denom)

def motion_heuristic(img1_bytes: bytes, img2_bytes: bytes) -> float:
    a = cv2.imdecode(np.frombuffer(img1_bytes, dtype=np.uint8), cv2.IMREAD_GRAYSCALE)
    b = cv2.imdecode(np.frombuffer(img2_bytes, dtype=np.uint8), cv2.IMREAD_GRAYSCALE)
    if a is None or b is None:
        return 0.0
    a = cv2.resize(a, (256, 256))
    b = cv2.resize(b, (256, 256))
    diff = cv2.absdiff(a, b)
    score = float(np.mean(diff)) / 255.0
    return score

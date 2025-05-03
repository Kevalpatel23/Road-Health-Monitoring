from ultralytics import YOLO
import os
import time

class ModelInference:
    def __init__(self, model_path):
        # Load the model
        self.__model_path = os.path.join("static", "model", "detection_model.pt")  # Cross-platform path
        self.model = YOLO(self.__model_path)  # Adjust as needed
        self.confidence_score = 0.0
        self.geolocation = None

    def predict(self, image_path) -> bool:
        # Perform inference on the provided image
        results = self.model(image_path)
        if results:
            for i, result in enumerate(results):
                if len(result.boxes):
                    # Get the confidence score of the detection
                    self.confidence_score = float(result.boxes.conf[0])
                    # Save the result
                    result.save(os.path.join(image_path))
                    return True
                else:
                    os.remove(image_path)
                    return False
        else:
            print("Results Empty!")  # TODO: fix this else with proper logging
            return False
        return True

    def set_geolocation(self, lat, lng):
        self.geolocation = (lat, lng)

    def process_detections(self, detections):
        # Process the detections to determine if a pothole is detected
        pothole_detected = any(detection[5] == 0 for detection in detections)  # Adjust class index as needed
        return pothole_detected, detections  # Return whether a pothole was detected and the raw detections

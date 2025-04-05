from ultralytics import YOLO
import os

class ModelInference:
    def __init__(self, model_path):
        # Load the model
        self.__model_path = model_path  # Use the provided model path
        self.model = YOLO(self.__model_path)  # Adjust as needed

    def predict(self, image_path) -> bool:
        # Perform inference on the provided image
        results = self.model(image_path)
        if results:
            for i, result in enumerate(results):
                if len(result.boxes):
                    result.save(os.path.join(image_path))  # Save each result
                else:
                    os.remove(image_path)
                    return False
        else:
            print("Results Empty!")  # TODO: fix this else with proper logging
            return False
        return True

    def process_detections(self, detections):
        # Process the detections to determine if a pothole is detected
        pothole_detected = any(detection[5] == 0 for detection in detections)  # Adjust class index as needed
        return pothole_detected, detections  # Return whether a pothole was detected and the raw detections

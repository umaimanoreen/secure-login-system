using UnityEngine;

// FIX: This script now supports BOTH Old and New Input Systems
public class CharacterMovement : MonoBehaviour
{
    public float speed = 5.0f;

    void Update()
    {
        float moveX = 0f;
        float moveZ = 0f;

        // Try-Catch to handle Input System conflict gracefully
        try {
            // Check legacy input first
            if (Input.GetKey(KeyCode.LeftArrow)) moveX = -1f;
            else if (Input.GetKey(KeyCode.RightArrow)) moveX = 1f;

            if (Input.GetKey(KeyCode.UpArrow)) moveZ = 1f;
            else if (Input.GetKey(KeyCode.DownArrow)) moveZ = -1f;
        }
        catch (System.InvalidOperationException) {
            // If New Input System is active, fallback warning or alternative logic
            // Ideally, switch Project Settings -> Player -> Active Input Handling to "Both"
            Debug.LogError("Please go to Edit > Project Settings > Player > Other Settings > Active Input Handling and set it to 'Both' or 'Input Manager (Old)'");
        }

        Vector3 movement = new Vector3(moveX, 0.0f, moveZ);
        transform.Translate(movement * speed * Time.deltaTime);
    }
}

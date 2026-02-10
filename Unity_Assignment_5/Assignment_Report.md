# Assignment 5 Report
**Course:** Human-Computer Interaction & Computer Graphics  
**Date:** January 14, 2026  
**Group Members:** [Name 1], [Name 2], [Name 3]

## Task 1: Character Asset Import
I have successfully imported a free character asset from the Unity Asset Store into the scene created in Assignment 4.
*(Place Screenshot of your character in the scene here)*

## Task 2: Transformation Script (Movement)

### 1. Script
The following C# script (`CharacterMovement.cs`) was created to handle character movement using the arrow keys. It uses `transform.Translate` to modify the position of the character based on keyboard input.

```csharp
using UnityEngine;

public class CharacterMovement : MonoBehaviour
{
    // Speed of the character
    public float speed = 5.0f;

    void Update()
    {
        float moveX = 0f;
        float moveZ = 0f;

        // Left Arrow -> Move Left (Negative X)
        if (Input.GetKey(KeyCode.LeftArrow))
        {
            moveX = -1f;
        }
        // Right Arrow -> Move Right (Positive X)
        else if (Input.GetKey(KeyCode.RightArrow))
        {
            moveX = 1f;
        }

        // Up Arrow -> Move Forward (Positive Z)
        if (Input.GetKey(KeyCode.UpArrow))
        {
            moveZ = 1f;
        }
        // Down Arrow -> Move Backward (Negative Z)
        else if (Input.GetKey(KeyCode.DownArrow))
        {
            moveZ = -1f;
        }

        Vector3 movement = new Vector3(moveX, 0.0f, moveZ);
        transform.Translate(movement * speed * Time.deltaTime);
    }
}
```

### 2. Screenshots
Below are screenshots of the character at different places in the scene after applying the movement script.

**Screenshot 1: Initial Position**  
*(Paste Screenshot Here)*

**Screenshot 2: Character Moved Left**  
*(Paste Screenshot Here - Show character moved to the left)*

**Screenshot 3: Character Moved Forward**  
*(Paste Screenshot Here - Show character moved forward)*

---
**Instructions for Submission:**
1. Open this report in a markdown editor or copy the text to a Word document.
2. Replace **[Name 1], [Name 2]...** with actual group member names.
3. Take screenshots from your Unity Scene and paste them in the designated areas.
4. Submit via Tasjeel Portal.

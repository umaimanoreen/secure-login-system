using UnityEngine;

public class ClassroomGenerator : MonoBehaviour
{
    // Increased Dimensions to ensure it fits ALMOST any furniture setup
    public float width = 25f;
    public float length = 25f;
    public float height = 6f;

    // Materials
    public Material floorMat, wallMat, roofMat;

    void Start()
    {
        // 1. FORCE CENTER the container object
        this.transform.position = Vector3.zero; 
        this.transform.rotation = Quaternion.identity;

        BuildRoomStructure();
    }

    void BuildRoomStructure()
    {
        // 1. Floor (Centered at 0,0,0)
        GameObject floor = GameObject.CreatePrimitive(PrimitiveType.Plane);
        floor.name = "Classroom_Floor";
        floor.transform.parent = this.transform;
        floor.transform.position = Vector3.zero; 
        floor.transform.localScale = new Vector3(width / 10f, 1, length / 10f);
        if(floorMat) floor.GetComponent<Renderer>().material = floorMat;

        // 2. Roof
        GameObject roof = GameObject.CreatePrimitive(PrimitiveType.Cube);
        roof.name = "Classroom_Roof";
        roof.transform.parent = this.transform;
        roof.transform.position = new Vector3(0, height, 0);
        roof.transform.localScale = new Vector3(width, 0.2f, length);
        if(roofMat) roof.GetComponent<Renderer>().material = roofMat;

        // 3. Walls
        CreateWall("Wall_Back", new Vector3(0, height/2, -length/2), new Vector3(width, height, 0.5f));
        
        // --- WALL FRONT REMOVED FOR CAMERA VIEW ---
        // CreateWall("Wall_Front", new Vector3(0, height/2, length/2), new Vector3(width, height, 0.5f));

        CreateWall("Wall_Left", new Vector3(-width/2, height/2, 0), new Vector3(0.5f, height, length));
        CreateWall("Wall_Right", new Vector3(width/2, height/2, 0), new Vector3(0.5f, height, length));
    }

    void CreateWall(string name, Vector3 pos, Vector3 scale)
    {
        GameObject wall = GameObject.CreatePrimitive(PrimitiveType.Cube);
        wall.name = name;
        wall.transform.parent = this.transform;
        wall.transform.position = pos;
        wall.transform.localScale = scale;
        if(wallMat) wall.GetComponent<Renderer>().material = wallMat;
    }
}

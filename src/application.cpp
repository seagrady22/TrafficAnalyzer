#include "../include/application.hpp"
#include "../include/element_renderer.hpp"
#include <iostream>

void glfwErrorCallback(int error, const char* description) {
    std::cerr << "GLFW Error " << error << ": " << description << std::endl;
}

Application::Application() : window(nullptr), width(1280), height(720), selectedElement(nullptr) {
    initialize();
}

Application::~Application() {
    if (window) {
        glfwDestroyWindow(window);
    }
    glfwTerminate();
}

void Application::initialize() {
    std::cout << "Initializing GLFW..." << std::endl;
    glfwSetErrorCallback(glfwErrorCallback);
    
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return;
    }

    std::cout << "Creating window..." << std::endl;
    createWindow();
    std::cout << "Initializing OpenGL..." << std::endl;
    initializeOpenGL();
    std::cout << "Setting up elements..." << std::endl;
    setupElements();

    // Set up callbacks
    glfwSetWindowUserPointer(window, this);
    glfwSetMouseButtonCallback(window, mouseButtonCallback);
    glfwSetCursorPosCallback(window, mouseMoveCallback);
    glfwSetScrollCallback(window, scrollCallback);
    std::cout << "Initialization complete." << std::endl;
}

void Application::createWindow() {
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
    glfwWindowHint(GLFW_COCOA_RETINA_FRAMEBUFFER, GL_TRUE);

    window = glfwCreateWindow(width, height, "Chemical Visualizer", nullptr, nullptr);
    if (!window) {
        std::cerr << "Failed to create GLFW window" << std::endl;
        glfwTerminate();
        return;
    }

    glfwMakeContextCurrent(window);
}

void Application::initializeOpenGL() {
    std::cout << "GLEW version: " << glewGetString(GLEW_VERSION) << std::endl;
    
    GLenum err = glewInit();
    if (err != GLEW_OK) {
        std::cerr << "Failed to initialize GLEW: " << glewGetErrorString(err) << std::endl;
        return;
    }

    // Check OpenGL version
    const GLubyte* version = glGetString(GL_VERSION);
    const GLubyte* renderer = glGetString(GL_RENDERER);
    std::cout << "OpenGL Version: " << version << std::endl;
    std::cout << "OpenGL Renderer: " << renderer << std::endl;

    glEnable(GL_DEPTH_TEST);
    glEnable(GL_CULL_FACE);

    // Set up projection matrix
    projection = glm::perspective(glm::radians(45.0f), (float)width / (float)height, 0.1f, 100.0f);
    view = glm::lookAt(
        glm::vec3(0.0f, 5.0f, 10.0f),
        glm::vec3(0.0f, 0.0f, 0.0f),
        glm::vec3(0.0f, 1.0f, 0.0f)
    );

    // Check for OpenGL errors
    GLenum error = glGetError();
    if (error != GL_NO_ERROR) {
        std::cerr << "OpenGL error during initialization: " << error << std::endl;
    }
}

void Application::setupElements() {
    // Initialize the first 8 elements
    elements = {
        {ElementSymbol::H, "Hydrogen", 1, glm::vec3(1.0f, 1.0f, 1.0f), 1, glm::vec3(-3.0f, 0.0f, 0.0f), false},
        {ElementSymbol::He, "Helium", 2, glm::vec3(0.85f, 1.0f, 1.0f), 2, glm::vec3(-2.0f, 0.0f, 0.0f), false},
        {ElementSymbol::Li, "Lithium", 3, glm::vec3(0.8f, 0.5f, 1.0f), 1, glm::vec3(-1.0f, 0.0f, 0.0f), false},
        {ElementSymbol::Be, "Beryllium", 4, glm::vec3(0.76f, 1.0f, 0.0f), 2, glm::vec3(0.0f, 0.0f, 0.0f), false},
        {ElementSymbol::B, "Boron", 5, glm::vec3(1.0f, 0.71f, 0.71f), 3, glm::vec3(1.0f, 0.0f, 0.0f), false},
        {ElementSymbol::C, "Carbon", 6, glm::vec3(0.56f, 0.56f, 0.56f), 4, glm::vec3(2.0f, 0.0f, 0.0f), false},
        {ElementSymbol::N, "Nitrogen", 7, glm::vec3(0.19f, 0.31f, 0.97f), 5, glm::vec3(3.0f, 0.0f, 0.0f), false},
        {ElementSymbol::O, "Oxygen", 8, glm::vec3(1.0f, 0.05f, 0.05f), 6, glm::vec3(4.0f, 0.0f, 0.0f), false}
    };
}

void Application::run() {
    if (!window) {
        std::cerr << "Cannot run application: window is null" << std::endl;
        return;
    }

    std::cout << "Creating element renderer..." << std::endl;
    ElementRenderer renderer;
    std::cout << "Starting main loop..." << std::endl;

    // Set initial background color
    glClearColor(0.2f, 0.3f, 0.3f, 1.0f);

    int frameCount = 0;
    while (!glfwWindowShouldClose(window)) {
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
        
        update();
        
        // Render all elements
        for (const auto& element : elements) {
            renderer.render(element, view, projection);
        }
        
        glfwSwapBuffers(window);
        glfwPollEvents();

        // Print frame count every 60 frames
        frameCount++;
        if (frameCount % 60 == 0) {
            std::cout << "Frame: " << frameCount << std::endl;
        }

        // Check for OpenGL errors
        GLenum error = glGetError();
        if (error != GL_NO_ERROR) {
            std::cerr << "OpenGL error during rendering: " << error << std::endl;
        }
    }

    std::cout << "Main loop ended. Total frames: " << frameCount << std::endl;
}

void Application::update() {
    handleInput();
}

void Application::handleInput() {
    if (glfwGetKey(window, GLFW_KEY_ESCAPE) == GLFW_PRESS) {
        glfwSetWindowShouldClose(window, true);
    }
}

void Application::handleMouseButton(int button, int action, double x, double y) {
    if (button == GLFW_MOUSE_BUTTON_LEFT) {
        if (action == GLFW_PRESS) {
            // Convert screen coordinates to world coordinates
            float normalizedX = (2.0f * x) / width - 1.0f;
            float normalizedY = 1.0f - (2.0f * y) / height;
            
            // Find the closest element
            float minDistance = std::numeric_limits<float>::max();
            for (auto& element : elements) {
                glm::vec4 clipPos = projection * view * glm::vec4(element.position, 1.0f);
                glm::vec3 ndcPos = glm::vec3(clipPos) / clipPos.w;
                
                float distance = glm::distance(
                    glm::vec2(normalizedX, normalizedY),
                    glm::vec2(ndcPos.x, ndcPos.y)
                );
                
                if (distance < minDistance) {
                    minDistance = distance;
                    selectedElement = &element;
                }
            }
            
            if (selectedElement) {
                selectedElement->isDragging = true;
            }
        } else if (action == GLFW_RELEASE) {
            if (selectedElement) {
                selectedElement->isDragging = false;
                selectedElement = nullptr;
            }
        }
    }
}

void Application::handleMouseMove(double x, double y) {
    if (selectedElement && selectedElement->isDragging) {
        // Convert screen coordinates to world coordinates
        float normalizedX = (2.0f * x) / width - 1.0f;
        float normalizedY = 1.0f - (2.0f * y) / height;
        
        // Unproject the coordinates
        glm::mat4 inverseProjView = glm::inverse(projection * view);
        glm::vec4 worldPos = inverseProjView * glm::vec4(normalizedX, normalizedY, 0.0f, 1.0f);
        worldPos /= worldPos.w;
        
        selectedElement->position = glm::vec3(worldPos);
    }
}

void Application::handleScroll(double xoffset, double yoffset) {
    // Adjust the camera distance based on scroll
    glm::vec3 cameraPos = glm::vec3(0.0f, 5.0f, 10.0f);
    cameraPos.z += yoffset * 0.5f;
    view = glm::lookAt(
        cameraPos,
        glm::vec3(0.0f, 0.0f, 0.0f),
        glm::vec3(0.0f, 1.0f, 0.0f)
    );
}

void Application::mouseButtonCallback(GLFWwindow* window, int button, int action, int mods) {
    Application* app = static_cast<Application*>(glfwGetWindowUserPointer(window));
    double x, y;
    glfwGetCursorPos(window, &x, &y);
    app->handleMouseButton(button, action, x, y);
}

void Application::mouseMoveCallback(GLFWwindow* window, double x, double y) {
    Application* app = static_cast<Application*>(glfwGetWindowUserPointer(window));
    app->handleMouseMove(x, y);
}

void Application::scrollCallback(GLFWwindow* window, double xoffset, double yoffset) {
    Application* app = static_cast<Application*>(glfwGetWindowUserPointer(window));
    app->handleScroll(xoffset, yoffset);
} 